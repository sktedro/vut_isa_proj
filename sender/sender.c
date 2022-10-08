/**
 * @brief Sender for DNS tunneling
 * @file sender.c
 * @author Patrik Skaloš
 * @year 2022
 */

// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// Networking libraries
#include <arpa/inet.h>

// Header files
#include "sender.h"
#include "dns_sender_events.h"


// https://opensource.apple.com/source/netinfo/netinfo-208/common/dns.h.auto.html
struct dns_header_t{
    u_int16_t xid;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};
struct dns_question_info_t{
    u_int16_t type;
    u_int16_t class;
};


/*
 *
 * Global variables
 *
 */


char *UPSTREAM_DNS_IP = NULL;
char *BASE_HOST = NULL;
char *DST_FILEPATH = NULL;
char *SRC_FILEPATH = NULL;

FILE *SRC_FILE = NULL;

char *PAYLOAD = NULL;
char *PAYLOAD_B64 = NULL;


/*
 *
 * Misc functions
 *
 */


/**
 *
 * https://stackoverflow.com/a/6782480/17580261
 */
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};
char *base64_encode(const unsigned char *data,
                    int input_length,
                    int *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    /**
      * for (int i = 0; i < mod_table[input_length % 3]; i++)
      *     encoded_data[*output_length - 1 - i] = '=';
      */

    return encoded_data;
}


void err(char *format, ...){
    if(SRC_FILE){
        fclose(SRC_FILE);
    }
    if(PAYLOAD){
        free(PAYLOAD);
    }
    if(PAYLOAD_B64){
        free(PAYLOAD_B64);
    }
    fprintf(stderr, "Error! ");
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
    fprintf(stderr, "\n");
    exit(1);
}

/*
 *
 * Parsing arguments and getting required data
 *
 */





/**
 * @brief If the user didn't provide the upstream DNS IP, get it somehow else
 * because we need it... (I suppose)
 * TODO
 */
void get_UPSTREAM_DNS_IP(){
    // Get it from system resolvers
}


/**
 * @brief Parse user provided options to a structure
 *
 * @param argc
 * @param argv
 *
 * @return struct options
 */
void parse_args(int argc, char **argv){

    int positional_arg_count = 0;

    for(int i = 1; i < argc; i++){ // Start from one to ignore filename

        if(!strcmp(argv[i], "-u")){

            if(i + 1 >= argc){
                // If `-u` is the last argument -> error
                err("No argument following \"-u\"");
            }

            // Get the next arg and save it
            i += 1;
            UPSTREAM_DNS_IP = argv[i];

        }else{
            if(positional_arg_count == 0){
                // Arg is BASE_HOST
                BASE_HOST = argv[i];

            }else if(positional_arg_count == 1){
                // Arg is DST_FILEPATH
                DST_FILEPATH = argv[i];

            }else if(positional_arg_count == 2){
                // Arg is SRC_FILEPATH
                SRC_FILEPATH = argv[i];

            }else{
                fprintf(stderr, "Redundant argument provided: \"%s\". Ignoring.", argv[i]);
            }

            positional_arg_count += 1;
        }
    }
}



void check_args(){
    if(!BASE_HOST || !DST_FILEPATH){
        // If base host or dst filepath were not provided -> error
        err("Base host or Destination filepath argument missing.");
        exit(1);
    }

    if(!UPSTREAM_DNS_IP){
        // If no upstream DNS IP was provided in args, generate it or something
        get_UPSTREAM_DNS_IP();

    }else{
        // Else, check if the IP is valid
        // https://stackoverflow.com/questions/791982/determine-if-a-string-is-a-valid-ipv4-address-in-c
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, UPSTREAM_DNS_IP, &(sa.sin_addr));
        if(result == 0){
            err("Upstream DNS IP is invalid: \"%s\".", UPSTREAM_DNS_IP);
            exit(1);
        }
    }

    // Check if base host is valid
    for(int i = 0, n = strlen(BASE_HOST); i < n; i++){
        char c = BASE_HOST[i];
        // Check if it is a character that can be in a host name (alphanumeric,
        // '.' and '-')
        if(c != 46 && c != 45 && !(c >= 48 && c <= 57) && !(c <= 65 && c <= 90) && !(c >= 97 && c <= 122)){
            err("Invalid characters in base host: \'%c\'.", c);
        }
    }

    // Check if destination path is valid (src path will be checked when
    // opening)
    char forbidden_chars[] = "#%&{}\\<>*?$!'\":@+`|=";
    int forbidden_chars_len = strlen(forbidden_chars);
    for(int i = 0, n = strlen(DST_FILEPATH); i < n; i++){
        for(int j = 0; j < forbidden_chars_len; j++){
            if(DST_FILEPATH[i] == forbidden_chars[j]){
                err("Destination path contains forbidden characters: \'%c\'.", forbidden_chars[j]);
                exit(1);
            }
        }
    }
}




void get_payload(){

    // Set source file to stdin or provided path
    SRC_FILE = SRC_FILEPATH ? fopen(SRC_FILEPATH, "r") : stdin;
    if(!SRC_FILE){
        err("Could not open file \"%s\".", SRC_FILEPATH);
    }

    // Prepare payload string
    int payload_size = 1024;
    int payload_len = 0;
    PAYLOAD = malloc(payload_size);
    if(!PAYLOAD){
        err("Allocating memory failed.");
    }

    // Read from the file (or stdin) till EOF to payload string
    char c = '\0';
    while((c = fgetc(SRC_FILE)) != EOF){
        if(ferror(SRC_FILE)){
            err("Could not read from file provided");
        }

        // Realloc if the payload is filled
        if(payload_len + 4 > payload_size){
            payload_size *= 2;
            PAYLOAD = realloc(PAYLOAD, payload_size);
        }

        // Save the new char
        PAYLOAD[payload_len] = c;
        PAYLOAD[payload_len + 1] = '\0';
        payload_len += 1;
    }

    // Close the file
    fclose(SRC_FILE);
    SRC_FILE = NULL;


    printf("Payload: %s\n", PAYLOAD);
    // Encode payload to base64
    int PAYLOAD_B64_len = 0;
    PAYLOAD_B64 = base64_encode(PAYLOAD, strlen(PAYLOAD), &PAYLOAD_B64_len);
    if(!PAYLOAD_B64){
        err("Failed to convert input to base64");
    }
    printf("Base64: ");
    for(int i = 0; i < PAYLOAD_B64_len; i++){
        printf("%c", PAYLOAD_B64[i]);
    }
    printf("\n");

}















int main(int argc, char **argv){
    parse_args(argc, argv);
    check_args();

    get_payload();


    // Create a socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // UDP packet for DNS queries
    if(sock == -1){
        printf("%d\n", sock);
        err("Failed to open socket");
    }

    // Get destination address
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP);

    int dg_id = 0;
    int chars_sent = 0;
    while(dg_id != -1){

        // Create a DNS header
        unsigned char buffer[512] = {'\0'};
        struct dns_header_t *header = (struct dns_header_t *)buffer;
        header->xid = htons(9999); // Query ID (random)
        header->flags = htons(256); // 00000001 00000000b = 256: Standard query, desire recursion
        header->qdcount = htons(1); // Number of questions
        // Leave ancount (answers), nscount (authority RRs) and arcount (additional
        // RRs) as 0

        // Get pointer to question in the buffer (right after the header)
        unsigned char *question_tmp_ptr = &buffer[sizeof(struct dns_header_t)];


        // Create a prefix containing datagram ID followed by '-' save its
        // base64 equivalent
        char prefix[32] = {'\0'};
        sprintf(prefix, "%d", dg_id);
        prefix[strlen(prefix)] = '-';
        prefix[strlen(prefix)] = '\0';

        int prefix_b64_len = 0;
        char *prefix_b64 = base64_encode(prefix, strlen(prefix), &prefix_b64_len);
        if(!prefix_b64){
            err("Failed to convert to base64");
        }

        // Create datagram payload variable
        // Max length is 126 because we can use two labels with max len of 63
        // according to RFC1035
        char dg_payload[127] = {'\0'};

        // Copy prefix to dg_payload
        strncpy(dg_payload, prefix_b64, prefix_b64_len);

        if(dg_id == 0){
            // If this is the first packet, also include the destination path
        }


        // Copy payload (maximum that will fit) to dg_payload
        int chars_left = PAYLOAD_B64_len - chars_sent;
        int chars_to_copy = 126 - prefix_b64_len;
        if(chars_left < chars_to_copy){
            chars_to_copy = chars_left;
        }
        if(chars_to_copy != 0){
            strncpy(&dg_payload[prefix_b64_len], PAYLOAD_B64, chars_to_copy);
            chars_sent += chars_to_copy;
        }else{
            // If there are no more data to send, send the final datagram only
            // containing the prefix
            dg_id = -1;
        }


        // TODO Fill the question with dg_payload

        // Append first 63 bytes of the dg_payload
        u_int8_t label1_len = strlen(dg_payload);
        if(label1_len > 63){
            label1_len = 63;
        }
        question_tmp_ptr[0] = (unsigned char)label1_len;
        question_tmp_ptr += 1;
        for(int i = 0; i < label1_len; i++){
            question_tmp_ptr[i] = dg_payload[i];
        }
        question_tmp_ptr += label1_len;

        // Append second 63 bytes if needed
        u_int8_t label2_len = strlen(dg_payload) - label1_len;
        if(label2_len > 0){
            question_tmp_ptr[0] = (unsigned char)label2_len;
            question_tmp_ptr += 1;
            for(int i = label1_len, n = strlen(dg_payload); i < n; i++){
                question_tmp_ptr[0] = dg_payload[i];
                question_tmp_ptr += 1;
            }
        }

        // Get the third label - the domain name and append it to the question
        char name[126] = {'\0'};
        for(int i = 0, n = strlen(BASE_HOST); i < n; i++){
            if(BASE_HOST[i] == '.'){
                break;
            }
            name[i] = BASE_HOST[i];
        }
        u_int8_t name_len = strlen(name);
        question_tmp_ptr[0] = (unsigned char)name_len;
        question_tmp_ptr += 1;
        for(int i = 0; i < name_len; i++){
            question_tmp_ptr[i] = name[i];
        }
        question_tmp_ptr += name_len;

        // Get the final label - the domain extension and append it to the question
        char extension[126] = {'\0'};
        for(int i = 0, n = strlen(BASE_HOST) - strlen(name); i < n; i++){
            extension[i] = BASE_HOST[i + strlen(name) + 1];
        }
        u_int8_t extension_len = strlen(extension);
        question_tmp_ptr[0] = (unsigned char)extension_len;
        question_tmp_ptr += 1;
        for(int i = 0; i < extension_len; i++){
            question_tmp_ptr[i] = extension[i];
        }
        question_tmp_ptr += extension_len;

        // Finish the question name with 0x00
        question_tmp_ptr[0] = (unsigned char)0;
        question_tmp_ptr += 1;

        // Set type and class of the DNS query
        struct dns_question_info_t *question_info_ptr
            = (struct dns_question_info_t *)question_tmp_ptr;
        question_info_ptr->type = htons(1); // Type is A - host address
        question_info_ptr->class = htons(1); // Class is internet address
        question_tmp_ptr += 4;

        // Send the datagram

        // Packet length
        /** int len = sizeof(struct dns_header_t) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION) */
        int len = question_tmp_ptr - buffer;

        // Send the data
        int ret = sendto(sock, (char*)buffer, len, 0, (struct sockaddr*)&dst, sizeof(dst));
        if(ret < 0){
            err("Failed to send DNS query");
        }

        if(dg_id != -1){
            dg_id += 1;
        }

    }


    // max 250B domain name
    // max 64B label I guess
    // TODO MAX 4 labels + suffix

    /** fclose(SRC_FILE); */

    return 0;
}

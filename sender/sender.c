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
#include <sys/time.h>

// Networking libraries
#include <arpa/inet.h>

// Header files
#include "sender.h"
#include "dns_sender_events.h"


/**
 * DNS header structure
 * https://opensource.apple.com/source/netinfo/netinfo-208/common/dns.h.auto.html
 */
struct dns_header_t{
    u_int16_t xid;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};

/**
 * DNS question structure
 * https://opensource.apple.com/source/netinfo/netinfo-208/common/dns.h.auto.html
 */
struct dns_question_info_t{
    u_int16_t type;
    u_int16_t class;
};


/*
 *
 * GLOBAL VARIABLES
 *
 */


const int MAX_TRIES = 3; // Max tries for sending a packet

char *UPSTREAM_DNS_IP = NULL; // IP of DNS server provided by the user
char *UPSTREAM_DNS_IP_MALLOCD = NULL; // IP of DNS server from the system (if user didn't provide one)
char *BASE_HOST = NULL; // Hostname to use when sending a DNS request
char *DST_FILEPATH = NULL; // Path where to save the data on the server machine
char *SRC_FILEPATH = NULL; // Path to a file to send (null if file not provided)

FILE *SRC_FILE = NULL; // Open file or stdin

char *PAYLOAD_B64 = NULL; // Payload to send, encoded in base64, without padding
int PAYLOAD_B64_LEN = 0; // Length of payload in bytes

int QUERY_ID = 3285;


/*
 *
 * MISCELLANEOUS
 *
 */


/**
 * @brief Variables and functions for encoding a string to base64
 *
 * @param data to encode
 * @param input_length in characters
 * @param output_length - pointer where the output length in chars will be
 * written
 *
 * @return allocated string containing the output
 *
 * Taken and modified from: https://stackoverflow.com/a/6782480/17580261
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

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    // Remove '=' padding
    if(encoded_data[*output_length - 1] == '=') (*output_length)--;
    if(encoded_data[*output_length - 2] == '=') (*output_length)--;
    if(encoded_data[*output_length - 3] == '=') (*output_length)--;
    if(encoded_data[*output_length - 4] == '=') (*output_length)--;


    return encoded_data;
}


/**
 * @brief Free all resources, write the error message to stdout and exit
 *
 * @param As for printf and similar functions
 */
void err(char *format, ...){
    if(SRC_FILE){
        fclose(SRC_FILE);
    }
    free(UPSTREAM_DNS_IP_MALLOCD);
    free(PAYLOAD_B64);

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
 * PARSING ARGUMENTS AND PREPARING DATA
 *
 */


/**
 * @brief Get upstream DNS IP address from the system's /etc/resolv.conf and
 * save it to UPSTREAM_DNS_IP_MALLOCD (allocate it first)
 */
void get_upstream_dns_ip(){
    
    FILE *f = fopen("/etc/resolv.conf", "r");
    if(!f){
        err("\"/etc/resolv.conf\" could not be opened.");
    }

    char buffer[1024];
    while(fgets(buffer, 1024, f) != NULL){
        if(!strncmp(buffer, "nameserver ", strlen("nameserver "))){
            break;
        }
    }
    UPSTREAM_DNS_IP_MALLOCD = malloc(17 * sizeof(char));
    if(!UPSTREAM_DNS_IP_MALLOCD){
        err("Malloc failed");
    }
    strcpy(UPSTREAM_DNS_IP_MALLOCD, buffer + strlen("nameserver "));

    fclose(f);
}


/**
 * @brief Parse user provided options and save settings to global variables
 *
 * @param argc
 * @param argv
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


/**
 * @brief Validate arguments provided by the user: check if everything is
 * specified and in the right format. If not, raise an error.
 */
void check_args(){
    if(!BASE_HOST || !DST_FILEPATH){
        // If base host or dst filepath were not provided -> error
        err("Base host or Destination filepath argument missing.");
        exit(1);
    }

    if(!UPSTREAM_DNS_IP){
        // If no upstream DNS IP was provided in args, generate it or something
        get_upstream_dns_ip();

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


/**
 * @brief Read from the provided file to send or from STDIN to then encode it
 * to base64 and save it to a global variable
 */
void get_payload(){

    // Set source file to stdin or provided path
    SRC_FILE = SRC_FILEPATH ? fopen(SRC_FILEPATH, "rb") : stdin;
    if(!SRC_FILE){
        err("Could not open file \"%s\".", SRC_FILEPATH);
    }

    // Prepare payload string
    int payload_size = 1024;
    int payload_len = 0;
    unsigned char *payload = malloc(payload_size);
    if(!payload){
        err("Allocating memory failed.");
    }

    // Read from the file (or stdin) till EOF to payload string
    size_t read = 1024;
    while(read == 1024){

        // Realloc if there's not enough space
        if(payload_size < payload_len + 1024){
            payload_size *= 2;
            payload = realloc(payload, payload_size);
            if(!payload){
                err("Memory reallocation failed.");
            }
        }

        read = fread(payload + payload_len, 1, 1024, SRC_FILE);
        payload_len += read;
    }

    // Close the file
    fclose(SRC_FILE);
    SRC_FILE = NULL;


    // Encode payload to base64
    PAYLOAD_B64 = base64_encode(payload, payload_len, &PAYLOAD_B64_LEN);
    if(!PAYLOAD_B64){
        err("Failed to convert input to base64");
    }

    free(payload);
    payload = NULL;
}


/*
 *
 * TRANSMITTING AND RECEIVING DATA
 *
 */


/**
 * @brief Construct a DNS packet containing data provided to buffer and save its
 * length to buffer_len. 
 *
 * @param buffer - allocated output string
 * @param buffer_len - pointer to an integer - will contain packet length in
 * bytes
 * @param data - data to encapsulate in the packet
 * @param len - length of the data in bytes
 */
void create_packet(unsigned char *buffer, int *buffer_len, char *data, int len){

    // Create a DNS header
    struct dns_header_t *header = (struct dns_header_t *)buffer;
    header->xid = htons(QUERY_ID++); // Query ID (random)
    header->flags = htons(256); // 00000001 00000000b = 256: Standard query, desire recursion
    header->qdcount = htons(1); // Number of questions
    // Leave ancount (answers), nscount (authority RRs) and arcount (additional
    // RRs) as 0

    // Get pointer to question in the buffer (right after the header)
    unsigned char *question_tmp_ptr = &buffer[sizeof(struct dns_header_t)];

    // Label 1
    int len1 = len > 63 ? 63 : len;
    if(len1){
        *question_tmp_ptr = (unsigned char)len1;
        question_tmp_ptr += 1;
        for(int i = 0; i < len1; i++){
            question_tmp_ptr[i] = data[i];
        }
        question_tmp_ptr += len1;
    }
    
    // Label 2
    int len2 = len > 63 ? len - 63 : 0;
    if(len2){
        *question_tmp_ptr = (unsigned char)len2;
        question_tmp_ptr += 1;
        for(int i = 63; i < 63 + len2; i++){
            question_tmp_ptr[i - 63] = data[i];
        }
        question_tmp_ptr += len2;
    }

    int BASE_HOST_i = 0;

    // Domain name
    unsigned char *name_len_byte = question_tmp_ptr;
    question_tmp_ptr += 1;
    for( ; BASE_HOST[BASE_HOST_i] != '.'; BASE_HOST_i++){
        *question_tmp_ptr = BASE_HOST[BASE_HOST_i];
        question_tmp_ptr += 1;
    }
    *name_len_byte = (unsigned char)(question_tmp_ptr - name_len_byte - 1);

    BASE_HOST_i += 1; // Skip the '.'

    // Domain extension
    unsigned char *extension_len_byte = question_tmp_ptr;
    question_tmp_ptr += 1;
    for( ; BASE_HOST[BASE_HOST_i] != '\0'; BASE_HOST_i++){
        *question_tmp_ptr = BASE_HOST[BASE_HOST_i];
        question_tmp_ptr += 1;
    }
    *extension_len_byte = (unsigned char)(question_tmp_ptr - extension_len_byte - 1);

    // Terminate with zero byte
    *question_tmp_ptr = (unsigned char)'\0';
    question_tmp_ptr += 1;

    // Set type and class of the DNS query
    struct dns_question_info_t *question_info_ptr
        = (struct dns_question_info_t *)question_tmp_ptr;
    question_info_ptr->type = htons(1); // Type is A - host address
    question_info_ptr->class = htons(1); // Class is internet address
    question_tmp_ptr += 4;

    *buffer_len = question_tmp_ptr - buffer;
}


/**
 * @brief Send a packet through a socket to provided address
 *
 * @param sock - UDP socket
 * @param addr - sockaddr_in structure representing destination address
 * @param data - packet
 * @param len - packet length in bytes
 */
void send_packet(int sock, struct sockaddr_in addr, unsigned char *data, int len){
    int ret = sendto(sock, (char *)data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    if(ret != len){
        err("Failed to send a packet.");
    }
}


/**
 * @brief Receives data from the server. If no data is received (after a
 * constant timeout), return 1. Otherwise, return 0 since the confirmation was
 * received.
 *
 * @param sock - socket
 * @param addr - server address
 *
 * @return 0 if confirmation was received
 */
int wait_for_confirmation(int sock, struct sockaddr_in addr){
    char buffer[512] = {'\0'};
    int addr_len = sizeof(addr);
    int len = recvfrom(sock, buffer, 512, 0, (struct sockaddr *)&addr, &addr_len);
    return len > 0 ? 0 : 1;
}


/**
 * @brief Send an empty packet and ensure it is received. Try for a total of
 * MAX_TRIES if no confirmation is received from the server.
 *
 * @param sock - socket
 * @param addr - server address
 *
 * @return 0 if empty packet was sent successfully
 */
int ensure_send_empty(int sock, struct sockaddr_in addr){
    for(int i = 0; i < MAX_TRIES; i++){
        char packet[512] = {'\0'};
        int packet_len = 0;
        create_packet(packet, &packet_len, "", 0);
        send_packet(sock, addr, packet, packet_len);
        if(!wait_for_confirmation(sock, addr)){
            return 0;
        }
    }
    return 1;
}


/**
 * @brief Wait for confirmation (of packet receival) from the server. If none
 * comes, ensure that the server receives an empty message to close the
 * connection.
 *
 * @param sock - socket
 * @param addr - server address
 *
 * @return 0 if confirmation was received, 1 if a packet confirmation was not
 * received but connection was successfully closed, -1 if connection close
 * confirmation was not received
 */
int handle_confirmation(int sock, struct sockaddr_in addr){
    int ret = wait_for_confirmation(sock, addr);
    if(ret){
        // If we didn't receive the confirmation, send empty packet to finalize the
        // transfer and try to transfer again, from the start
        ret = ensure_send_empty(sock, addr);
        if(!ret){
            return 1;
        }else{
            return -1;
        }

    }
    return 0;
}


/**
 * @brief Transmit all base64 data in PAYLOAD_B64 in DNS packets to the server.
 * First packet will contain the destination file path, following packets will
 * contain the encoded data and the last packet will be empty, signaling
 * connection close.
 *
 * @return 0 if transmitted successfully, 1 if a packet confirmation was not
 * received but connection was successfully closed, -1 if connection close
 * confirmation was not received
 */
int transmit(){

    // Create a socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // UDP packet for DNS queries
    if(sock == -1){
        err("Failed to open socket");
    }

    // Set 1s receive timeout (for confirmation messages)
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 100000;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        err("Failed to set socket timeout option");
    }

    // Get destination address
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    // Use mallocd upstream DNS if it exists (user didn't specify '-u')
    if(UPSTREAM_DNS_IP_MALLOCD){
        dst.sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP_MALLOCD);
    }else{
        dst.sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP);
    }

    // Send the destination path
    int dst_path_b64_len = 0;
    char *dst_path_b64 = base64_encode(DST_FILEPATH, strlen(DST_FILEPATH), &dst_path_b64_len);
    char dst_path_packet[512] = {'\0'};
    int dst_path_packet_len = 0;
    create_packet(dst_path_packet, &dst_path_packet_len, dst_path_b64, dst_path_b64_len);
    send_packet(sock, dst, dst_path_packet, dst_path_packet_len);
    int ret = handle_confirmation(sock, dst);
    if(ret){
        return ret;
    }
    free(dst_path_b64);

    // Send all data:
    int bytes_sent = 0;
    while(bytes_sent < PAYLOAD_B64_LEN){

        // Take up to 126 bytes from PAYLOAD_B64 per packet
        char packet_payload[127] = {'\0'};
        int packet_payload_len = PAYLOAD_B64_LEN - bytes_sent;
        if(packet_payload_len > 126){
            packet_payload_len = 126;
        }
        strncpy(packet_payload, PAYLOAD_B64 + bytes_sent, packet_payload_len);

        // Create and send the packet
        char packet[512] = {'\0'};
        int packet_len = 0;
        create_packet(packet, &packet_len, packet_payload, packet_payload_len);
        send_packet(sock, dst, packet, packet_len);
        int ret = handle_confirmation(sock, dst);
        if(ret){
            return ret;
        }

        bytes_sent += packet_payload_len;
    }

    // Send empty packet to finalize the transfer
    return ensure_send_empty(sock, dst);
}


/*
 *
 * MAIN
 *
 */


int main(int argc, char **argv){

    // Parse and check arguments and save the payload to send (encode it first)
    parse_args(argc, argv);
    check_args();
    get_payload();

    int ret_val = 0;

    for(int i = 0; i < MAX_TRIES; i++){
        // Try to transmit the data. If it fails, try again for total of
        // MAX_TRIES. If that fails, return 2
        int ret = transmit();
        if(ret == 0){
            break;
        }else if(ret == -1){
            fprintf(stderr, "Try %d of %d for transmitting the data failed and connection could not be closed. Not trying again.\n", i + 1, MAX_TRIES);
            ret_val = 2;
            break;
        }
        
        fprintf(stderr, "Try %d of %d for transmitting the data failed.\n", i + 1, MAX_TRIES);
    }

    // Free resources
    if(SRC_FILE){
        fclose(SRC_FILE);
    }
    free(UPSTREAM_DNS_IP_MALLOCD);
    free(PAYLOAD_B64);

    if(ret_val){
        fprintf(stderr, "Could not transmit data. Is the server listening?");
    }

    return ret_val;
}

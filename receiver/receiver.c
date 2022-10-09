/**
 * @brief Receiver for DNS tunneling
 * @file receiver.c
 * @author Patrik Skaloš
 * @year 2022
 */

// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>

// Networking libraries
#include <arpa/inet.h>

// Header files
#include "receiver.h"
#include "dns_receiver_events.h"


// https://opensource.apple.com/source/netinfo/netinfo-208/common/dns.h.auto.html
struct dns_header_t{
    u_int16_t xid;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};



/*
 *
 * GLOBAL VARIABLES
 *
 */


char *BASE_HOST = NULL;
char *DST_FILEPATH = NULL; // Folder where to save files

char *DST_PATH = NULL; // Real path where to save the net file
char *DATA_B64 = NULL;
int DATA_B64_SIZE = 0;
int DATA_B64_LEN = 0;


/*
 *
 * MISCELLANEOUS
 *
 */


/**
 * @brief Variables and functions for decoding a string from base64
 *
 * @param data to decode
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
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}
unsigned char *base64_decode(const char *data,
        int input_length,
        int *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}
void base64_cleanup() {
    free(decoding_table);
}


/**
 * @brief Free all resources, write the error message to stdout and exit
 *
 * @param As for printf and similar functions
 */
void err(char *format, ...){
    free(DST_PATH);
    free(DATA_B64);
    free(decoding_table);

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
 * PARSING ARGUMENTS
 *
 */


/*
 * @brief Save arguments or raise an error
 *
 * @param argc
 * @param argc
 */
void parse_args(int argc, char **argv){
    if(argc != 3){
        err("Invalid amount of arguments");
    }
    BASE_HOST = argv[1];
    DST_FILEPATH = argv[2];
}


/**
 * @brief Check arguments validity - check if destination file path exists and
 * if the base host is a valid url
 */
void check_args(){
    // Check if base host is valid
    for(int i = 0, n = strlen(BASE_HOST); i < n; i++){
        char c = BASE_HOST[i];
        // Check if it is a character that can be in a host name (alphanumeric,
        // '.' and '-')
        if(c != 46 && c != 45 && !(c >= 48 && c <= 57) && !(c <= 65 && c <= 90) && !(c >= 97 && c <= 122)){

            err("Invalid characters in base host: \'%c\'.", c);
        }
    }

    struct stat sb;
    if(stat(DST_FILEPATH, &sb) != 0 || !S_ISDIR(sb.st_mode)){
        err("Destination path invalid or doesn't exist.");
    }
}


/*
 *
 * RECEIVING, PARSING AND SAVING DATA
 *
 */


/**
 * @brief Extract b64 payload from a packet received
 *
 * @param payload_b64 - pointer where to save the payload
 * @param buffer - packet
 * @param buffer_len - packet length in bytes
 */
void get_payload(char *payload_b64, char *buffer, int buffer_len){

    // Skip the header to get to the question
    unsigned char *query_tmp_ptr = &buffer[sizeof(struct dns_header_t)];

    // Get the question URL
    unsigned char url[512] = {'\0'};
    while(1){

        // Get label length: first byte
        u_int8_t label_len = (u_int8_t)(*query_tmp_ptr);
        query_tmp_ptr += 1;

        // If label length is zero, this is end of labels
        if(label_len == 0){
            break;
        }

        // Otherwise, write the label to 'url'
        for(int i = 0; i < label_len; i++){
            url[strlen(url)] = *query_tmp_ptr;
            query_tmp_ptr += 1;
        }
        url[strlen(url)] = '.';
    }
    url[strlen(url) - 1] = '\0'; // Remove the trailing '.'

    // Check the domain - compare url and base host by characters from the
    // end
    int equal = 1;
    for(int BASE_HOST_i = strlen(BASE_HOST) - 1, url_i = strlen(url) - 1;
            BASE_HOST_i >= 0 && url_i >= 0; 
            BASE_HOST_i--, url_i--){
        if(BASE_HOST[BASE_HOST_i] != url[url_i]){
            equal = 0;
            break;
        }
    }
    if(!equal){
        // If the domain is not what the user set up, ignore this packet
        continue;
    }

    // Get the real payload, without the domain - iter from the end, char
    // by char and only start copying characters after encountering the
    // second '.'. Then, still ignore the '.' characters
    int ignore = 2;
    for(int i = strlen(url) - 1; i >= 0; i--){
        if(url[i] == '.' && ignore){
            ignore -= 1;
        }
        if(!ignore){
            payload_b64[i] = url[i];
        }
    }

    // Remove all '.' from the labels
    for(int i = 0; i < strlen(payload_b64); i++){
        if(payload_b64[i] == '.'){
            for(int j = i; j < strlen(payload_b64); j++){
                payload_b64[j] = payload_b64[j + 1];
            }
        }
    }
}




/**
 * @param Handle the first packet of a communication - extract the payload
 * (path, where to save the upcoming data), save it and prepare everything for
 * the communication
 *
 * @param payload_b64 - base64 payload in the packet
 */
void handle_first_payload(char *payload_b64){
    
    // Add padding back to the b64 and decode it
    while(strlen(payload_b64) % 4 != 0){
        payload_b64[strlen(payload_b64)] = '=';
    }
    int payload_len = 0;
    char *payload = base64_decode(payload_b64, strlen(payload_b64), &payload_len);

    // Fill the DST_PATH variable
    DST_PATH = malloc(512);
    if(!DST_PATH){
        err("Could not allocate memory");
    }
    strcpy(DST_PATH, DST_FILEPATH);
    DST_PATH[strlen(DST_PATH)] = '/';
    strncpy(DST_PATH + strlen(DST_PATH), payload, payload_len);

    free(payload);

    // Allocate DATA_B64 var
    if(!DATA_B64){
        DATA_B64 = malloc(512);
        if(!DATA_B64){
            err("Failed to allocate memory");
        }
        DATA_B64_SIZE = 512;
        DATA_B64_LEN = 0;
    }
}

/**
 * @brief Handles a payload which is not the first and not the last packet - so
 * just append the payload to DATA_B64 string, which will be decoded and saved
 * to file at the end
 *
 * @param payload_b64 - payload in the packet, encoded in base64
 */
void handle_next_payload(char *payload_b64){

    // Realloc DATA_B64 if it's too small
    if(DATA_B64_SIZE <= DATA_B64_LEN + strlen(payload_b64) + 8){ // 8 for future b64 padding, null byte, ...
        DATA_B64 = realloc(DATA_B64, DATA_B64_SIZE * 2);
        if(!DATA_B64){
            err("Failed to allocate memory.");
        }
        DATA_B64_SIZE *= 2;
    }
    printf("b64 p: %s\n", payload_b64);

    // Copy payload to DATA_B64
    strcpy(DATA_B64 + DATA_B64_LEN, payload_b64);
    DATA_B64_LEN += strlen(payload_b64);
}


/**
 * @param Handle the final message of a communication - decode the received
 * data, save it to a provided file and free all resources
 */
void handle_fin_msg(){
    // Add padding back to the b64
    while(strlen(DATA_B64) % 4 != 0){
        DATA_B64[strlen(DATA_B64)] = '=';
    }
    printf("all b64: %s\n", DATA_B64);

    // Decode b64 data and write it to a file
    int data_len = 0;
    char *data = base64_decode(DATA_B64, DATA_B64_LEN, &data_len);

    printf("data:");
    for(int i = 0; i < data_len; i++)
        printf("%c", data[i]);
    printf("\n");

    // Save to file
    FILE *f = fopen(DST_PATH, "w");
    if(!f){
        err("Could not open destination file");
    }
    for(int i = 0; i < data_len; i++){
        if(data[i] != '\0'){
            fputc(data[i], f);
        }
    }
    fclose(f);

    free(data);
    free(DST_PATH);
    DST_PATH = NULL;
    free(DATA_B64);
    DATA_B64 = NULL;
    DATA_B64_SIZE = 0;
    DATA_B64_LEN = 0;
}


/*
 *
 * MAIN
 *
 */


int main(int argc, char **argv){

    // Parse and check args
    parse_args(argc, argv);
    check_args();

    // Create a socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1){
        err("Failed to open socket");
    }

    // Set reuse address option
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

    // Bind socket to port 53
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(53); // DNS port = 53
    if(bind(sock, (struct sockaddr *)&server, sizeof(server))){
        err("Failed to bind socket to port 53.\n");
    }

    // Prep client address
    struct sockaddr_in client;
    int client_len = sizeof(client);

    // Prep buffer
    unsigned char buffer[512];

    int first_packet_received = 0; // 1 if there is an open communication

    // Receive in a loop
    while(1){

        // Receive
        int buffer_len = recvfrom(sock, buffer, 512, 0, (struct sockaddr *)&client, &client_len);

        // Get payload in b64 from the packet
        unsigned char payload_b64[256] = {'\0'};
        get_payload(payload_b64, buffer, buffer_len);

        if(!first_packet_received){
            // We received a destination file path - decode and save it
            handle_first_payload(payload_b64);
            first_packet_received = 1;

        }else if(strlen(payload_b64)){
            // If this is not empty - not a fin message, it is just the next
            // payload to save
            handle_next_payload(payload_b64);

        }else{
            // If the message is empty, it is the fin message (connection
            // close)
            handle_fin_msg();
            first_packet_received = 0;
        }

        // TODO Send confirmation response - the same packet as received should
        // suffice I guess
        int sent_len = sendto(sock, &buffer, buffer_len, MSG_CONFIRM, (struct sockaddr *)&client, client_len);
    }

    // Clear resources
    free(DST_PATH);
    free(DATA_B64);
    free(decoding_table);

    return 0;
}

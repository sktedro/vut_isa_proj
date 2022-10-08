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

// Networking libraries
#include <arpa/inet.h>

// Header files
#include "receiver.h"
#include "dns_receiver_events.h"


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
 * Global variables
 *
 */


char *base_host = NULL;
char *dst_filepath = NULL;

char **DATA = NULL;
int DATA_SIZE = 0;

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

void err(char *format, ...){
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

void parse_args(int argc, char **argv){
    if(argc != 3){
        err("Invalid amount of arguments");
    }
    base_host = argv[1];
    dst_filepath = argv[2];
}

void check_args(){
    // Check if base host is valid
    for(int i = 0, n = strlen(base_host); i < n; i++){
        char c = base_host[i];
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
    for(int i = 0, n = strlen(dst_filepath); i < n; i++){
        for(int j = 0; j < forbidden_chars_len; j++){
            if(dst_filepath[i] == forbidden_chars[j]){
                err("Destination path contains forbidden characters: \'%c\'.", forbidden_chars[j]);
                exit(1);
            }
        }
    }
}






int main(int argc, char **argv){

    parse_args(argc, argv);
    check_args();


    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(!sock){
        err("Failed to open socket");
    }

    // Bind socket to port 53
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    /** server.sin_addr.s_addr = INADDR_ANY; */
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(53); // DNS port = 53
    if(bind(sock, (struct sockaddr *)(&server), sizeof(server))){
        err("Failed to bind socket to port 53.\n");
    }

    // Receive in a loop
    unsigned char buffer[512] = {'\0'};
    int received_fin_msg = 0;
    while(1){

        struct sockaddr client;

        // Receive
        int client_len = sizeof(client);
        int datagram_len = recvfrom(sock, &buffer, 512, 0, &client, &client_len);

        // Skip the header to get to the query
        unsigned char *query_tmp_ptr = &buffer[sizeof(struct dns_header_t)];

        // Max 4 labels, label max len = 63 bytes
        char labels[4][64] = {'\0', '\0', '\0', '\0'};
        int labels_amount = 0;

        // Parse labels (max 4)
        for(int i = 0; i < 4; i++){

            u_int8_t label_len = *((u_int8_t*)query_tmp_ptr);

            // In case there are less than 4 labels
            if(label_len == 0){
                break;
            }

            // Copy label
            for(int j = 0; j < label_len; j++){
                labels[i][j] = query_tmp_ptr[1 + j];
            }
            query_tmp_ptr += 1 + label_len;

            labels_amount += 1;
        }

        printf("Labels: %s.%s.%s.%s\n", labels[0], labels[1], labels[2], labels[3]);

        // Check if last two labels are the same as base_host. If not, ignore
        // this packet
        char tmp[256] = {'\0'};
        strcpy(tmp, labels[labels_amount - 2]);
        tmp[strlen(tmp)] = '.';
        strcat(tmp, labels[labels_amount - 1]);
        if(strcmp(tmp, base_host)){
            continue;
        }

        // Get data
        char data_b64[127] = {'\0'};
        strcpy(data_b64, labels[0]);
        if(labels_amount == 4){
            // If we have 4 labels, two of them contain data
            strcat(data_b64, labels[1]);
        }

        printf("Data b64: %s\n", data_b64);

        // Decode the data
        int data_len = 0;
        char *data = base64_decode(data_b64, strlen(data_b64), &data_len);
        printf("Decoded: ");
        for(int i = 0; i < data_len; i++){
            printf("%c", data[i]);
        }
        printf("\n");


        // Get prefix
        char prefix[32] = {'\0'};
        for(int i = 0; i < 32; i++){
            if(data[i] == '-'){
                break;
            }
            prefix[i] = data[i];
        }

        // Get datagram ID from prefix
        int dg_id = strtol(prefix, NULL, 10);

        // If the payload is empty, set received_fin_msg to true
        received_fin_msg = 1;

        // Save the datagram payload to DATA
        if(!DATA){
            DATA = malloc(sizeof(char *) * 2);
            DATA_SIZE = 2;
            DATA[0] = NULL;
            DATA[1] = NULL;
        }
        // If DATA is too short for this datagram, realloc
        if(DATA_SIZE < dg_id + 1){
            DATA = realloc(data, DATA_SIZE * 2);
            // Set new elements to NULL
            for(int i = DATA_SIZE; i < DATA_SIZE * 2; i++){
                DATA[i] = NULL;
            }
            DATA_SIZE *= 2;
        }
        if(DATA[dg_id]){
            err("Received a second datagram with the same ID. Communication is compromised.");
        }
        DATA[dg_id] = malloc(sizeof(char) * (data_len - strlen(prefix) + 1));
        strcpy(DATA[dg_id], data + strlen(prefix));

        // If we have all messages, we can save them to a file

        if(received_fin_msg){

            // Get the highest ID of all datagrams received
            int last_dg_index = dg_id;
            for(int i = last_dg_index; i < DATA_SIZE; i++){
                if(DATA[i]){
                    last_dg_index = i;
                }
            }

            int all_datagrams_received = 1;
            for(int i = 0; i < last_dg_index; i++){
                if(!DATA[i]){
                    all_datagrams_received = 0;
                    break;
                }
            }

            if(all_datagrams_received){

                // TODO send answer

                // TODO read where to save

                // TODO save to file
                
                // TODO free DATA var
                for(int i = 0; i < DATA_SIZE; i++){
                    free(DATA[i]);
                }
                free(DATA);

                received_fin_msg = 0;

            }
        }
        




        /** sendto(sock,&Reply,ReplyLen,0,&client,client_len); */

    }









    return 0;
}

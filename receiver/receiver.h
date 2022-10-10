/**
 * @brief Receiver for DNS tunneling
 * @file receiver.h
 * @author Patrik Skaloš
 * @year 2022
 */


// Standard libraries
#include <stdlib.h>


/**
 * DNS header structure
 * Taken from: https://opensource.apple.com/source/netinfo/netinfo-208/common/dns.h.auto.html
 */
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
void build_decoding_table();
unsigned char *base64_decode(const char *data, int input_length, int *output_length);
void base64_cleanup();


/**
 * @brief Free all resources, write the error message to stdout and exit
 *
 * @param As for printf and similar functions
 */
void err(char *format, ...);


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
void parse_args(int argc, char **argv);


/**
 * @brief Check arguments validity - check if destination file path exists and
 * if the base host is a valid url
 */
void check_args();


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
 * @param query_id - pointer where to save xid from the header
 */
void get_payload(char *payload_b64, char *buffer, int buffer_len, int *query_id);


/**
 * @param Handle the first packet of a communication - extract the payload
 * (path, where to save the upcoming data), save it and prepare everything for
 * the communication
 *
 * @param payload_b64 - base64 payload in the packet
 */
void handle_first_payload(char *payload_b64);


/**
 * @brief Handles a payload which is not the first and not the last packet - so
 * just append the payload to DATA_B64 string, which will be decoded and saved
 * to file at the end
 *
 * @param payload_b64 - payload in the packet, encoded in base64
 */
void handle_next_payload(char *payload_b64);


/**
 * @param Handle the final message of a communication - decode the received
 * data, save it to a provided file and free all resources
 */
void handle_fin_msg();

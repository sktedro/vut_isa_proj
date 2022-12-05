/**
 * @brief Sender for DNS tunneling
 * @file dns_sender.h
 * @author Patrik Skaloš
 * @year 2022
 */


// Standard libraries
#include <stdlib.h>
#include <stdint.h>

// Networking libraries
#include <arpa/inet.h>
#include <netinet/in.h>


/**
 * DNS header structure
 * https://opensource.apple.com/source/netinfo/netinfo-208/common/dns.h.auto.html
 */
struct dns_header_t{
    uint16_t xid;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};


/**
 * DNS question structure
 * https://opensource.apple.com/source/netinfo/netinfo-208/common/dns.h.auto.html
 */
struct dns_question_info_t{
    uint16_t type;
    uint16_t class;
};


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
char *base64_encode(const unsigned char *data, int input_length, int *output_length);


/**
 * @brief Free all resources, write the error message to stdout and exit
 *
 * @param As for printf and similar functions
 */
void err(char *format, ...);


/*
 *
 * PARSING ARGUMENTS AND PREPARING DATA
 *
 */


/**
 * @brief Get upstream DNS IP address from the system's /etc/resolv.conf and
 * save it to UPSTREAM_DNS_IP_MALLOCD (allocate it first)
 */
void get_upstream_dns_ip();


/**
 * @brief Parse user provided options and save settings to global variables
 *
 * @param argc
 * @param argv
 */
void parse_args(int argc, char **argv);


/**
 * @brief Validate arguments provided by the user: check if everything is
 * specified and in the right format. If not, raise an error.
 */
void check_args();


/**
 * @brief Read from the provided file to send or from STDIN to then encode it
 * to base64 and save it to a global variable
 */
void get_payload();


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
void create_packet(unsigned char *buffer, int *buffer_len, char *data, int len);


/**
 * @brief Send a packet through a socket to provided address
 *
 * @param sock - UDP socket
 * @param addr - sockaddr_in structure representing destination address
 * @param data - packet
 * @param len - packet length in bytes
 */
void send_packet(int sock, struct sockaddr_in addr, unsigned char *data, int len);


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
int wait_for_confirmation(int sock, struct sockaddr_in addr);


/**
 * @brief Send an empty packet and ensure it is received. Try for a total of
 * MAX_TRIES if no confirmation is received from the server.
 *
 * @param sock - socket
 * @param addr - server address
 *
 * @return 0 if empty packet was sent successfully
 */
int ensure_send_empty(int sock, struct sockaddr_in addr);


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
int handle_confirmation(int sock, struct sockaddr_in addr);


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
int transmit();

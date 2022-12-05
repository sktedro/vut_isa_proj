# DNS tunneling tool

Two programs are present, `dns_sender` and `dns_receiver`, which respectively
send and receive data only using DNS datagrams over UDP, while data are encoded
to Base64 format.

The sender tries sending the data up to three times and with every packet, it
expects a response from the receiver. If no response is received, sender tries
to close the connection up to three times, and if the receiver responds to a
connection-closing datagram, the communication is established again and
transmission starts from the beginning. If, however, the connection could not
be closed, the sender cannot send more data as they would confuse the receiver
and the transmission is cancelled.

Patrik Skaloš (xskalo01), 2022


# Usage

## Sender

`dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]`

where:
- `UPSTREAM_DNS_IP` - IPv4 address of the DNS server to use. If not specified,
  first entry from `resolv.conf` is used
- `BASE_HOST` - domain (eg. `example.com`) to use in DNS datagrams
- `DST_FILEPATH` - path (relative) on the receiver's machine where to save the
  transmitted data
- `SRC_FILEPATH` - path (relative or absolute) to a file to send to the
  receiver. If not specified, input from STDIN is used instead

#### Example:

`dns_sender -u 192.168.129.99 example.com file_received.txt file_to_send.txt`


## Receiver

`dns_receiver {BASE_HOST} {DST_DIRPATH}`

where:
- `BASE_HOST` - domain (eg. `example.com`) to expect in incoming DNS datagrams
- `DST_DIRPATH` - path (relative or absolute) on the machine where to save
  files received from the sender

#### Example:

`dns_receiver example.com files_received/`


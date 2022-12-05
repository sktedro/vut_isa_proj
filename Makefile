SEND_PATH=sender
SEND_NAME=dns_sender
SEND_FILE_PATH=${SEND_PATH}/${SEND_NAME}
SEND_EVENTS_PATH=${SEND_PATH}/dns_sender_events

RECV_PATH=receiver
RECV_NAME=dns_receiver
RECV_FILE_PATH=${RECV_PATH}/${RECV_NAME}
RECV_EVENTS_PATH=${RECV_PATH}/dns_receiver_events


.PHONY: sender receiver


all: sender receiver


sender:
	@gcc -g -o ${SEND_FILE_PATH} ${SEND_FILE_PATH}.c ${SEND_FILE_PATH}.h ${SEND_EVENTS_PATH}.c ${SEND_EVENTS_PATH}.h


receiver:
	@gcc -g -o ${RECV_FILE_PATH} ${RECV_FILE_PATH}.c ${RECV_FILE_PATH}.h ${RECV_EVENTS_PATH}.c ${RECV_EVENTS_PATH}.h


run_sender: sender
	sudo bash -c "./${SEND_FILE_PATH} -u 127.0.0.1 tedro.com ./data.txt <<< 'Sup?'"


run_receiver: receiver
	sudo ./${RECV_FILE_PATH} tedro.com ./data


clean:
	rm -f ${SEND_FILE_PATH}
	rm -f ${RECV_FILE_PATH}
	rm -rf data
	rm -rf xskalo01
	rm -f xskalo01.tar

pack: clean
	mkdir xskalo01
	mkdir xskalo01/sender
	mkdir xskalo01/receiver
	cp receiver/dns_receiver.* xskalo01/receiver/
	cp sender/dns_sender.* xskalo01/sender/
	cp doc/doc.pdf xskalo01/manual.pdf
	cp README.md xskalo01/
	cp Makefile xskalo01/
	tar -cvf xskalo01.tar xskalo01/receiver/ xskalo01/sender/ xskalo01/manual.pdf xskalo01/Makefile xskalo01/README.md
	rm -rf xskalo01

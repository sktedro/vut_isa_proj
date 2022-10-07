SEND_PATH=sender/
SEND_NAME=sender
SEND_FILE_PATH=${SEND_PATH}/${SEND_NAME}
SEND_EVENTS_PATH=${SEND_PATH}/dns_sender_events

RECV_PATH=receiver/
RECV_NAME=receiver
RECV_FILE_PATH=${RECV_PATH}/${RECV_NAME}
RECV_EVENTS_PATH=${RECV_PATH}/dns_receiver_events



all: sender receiver


sender:
	gcc ${SEND_FILE_PATH}.c ${SEND_FILE_PATH}.h ${SEND_EVENTS_PATH}.c ${SEND_EVENTS_PATH}.h -o ${SEND_FILE_PATH}


receiver:
	gcc ${RECV_FILE_PATH}.c ${RECV_FILE_PATH}.h ${RECV_EVENTS_PATH}.c ${RECV_EVENTS_PATH}.h -o ${RECV_FILE_PATH}


run_sender:
	./${SEND_FILE_PATH} -b tedro.com -u 127.0.0.1 ./data.txt <<< "Sup?"


run_receiver:
	./${RECV_FILE_PATH} tedro.com ./data


pack:
	@echo "TODO"

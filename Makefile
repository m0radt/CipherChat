CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c17 -pthread

COMMON_SOURCES = common.c file_protocol.c network.c
SERVER_SOURCES = server.c server_worker.c client_manager.c command_parser.c server_files.c \
	server_file_routes.c server_messages.c $(COMMON_SOURCES)
CLIENT_SOURCES = client.c client_file_sender.c client_file_receiver.c \
	$(COMMON_SOURCES)

.PHONY: all clean test

all: server client

server: $(SERVER_SOURCES) common.h file_protocol.h network.h client_manager.h \
	command_parser.h server_files.h server_file_routes.h server_messages.h server_worker.h
	$(CC) $(CFLAGS) $(SERVER_SOURCES) -o server -lssl -lcrypto

client: $(CLIENT_SOURCES) client_files.h common.h file_protocol.h network.h
	$(CC) $(CFLAGS) $(CLIENT_SOURCES) -o client -lreadline -lssl -lcrypto

test: all
	python3 tests/integration_test.py
	python3 tests/tls_failure_test.py
	python3 tests/server_worker_test.py
	python3 tests/tls_lifecycle_test.py

clean:
	rm -f server client

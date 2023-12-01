CC=gcc
CFLAGS=-I.
OBJ = main.o
LIBS=-lssl -lcrypto -lpthread 

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

server: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean install_dependencies generate_cert

debug:  $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) -g

clean:
	rm -f *.o *~ core server

install_deps:
	sudo apt update
	sudo apt install libssl-dev

generate_cert:
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"


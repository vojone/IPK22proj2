BIN = ipk-sniffer
SRCS = ipk-sniffer.cpp

ARCHIVENAME = xdvora3o.tar
INARCHIVE = $(SRCS)

all:
	g++ -std=gnu++11 -Wall -Wextra -pedantic $(SRCS) -o $(BIN) -lpcap

run:
	./$(BIN)

tar:
	tar -cf $(ARCHIVENAME) $(INARCHIVE)

clean:
	rm -f $(BIN) $(ARCHIVENAME) 

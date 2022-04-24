BIN = ipk-sniffer
SRCS = ipk-sniffer.cpp

ARCHIVENAME = xdvora3o.tar
INARCHIVE = $(SRCS) README.md manual.pdf Makefile

all:
	g++ -std=gnu++11 -Wall -Wextra -pedantic $(SRCS) -o $(BIN) -lpcap

run:
	./$(BIN)

tar:
	tar -cf $(ARCHIVENAME) $(INARCHIVE)


#Basic test cases
#IMPORTANT: To run this, it needs nping to be installed and IPv6 to be supported
#AND needs to be run with -Bi (always execute and ignore errors mode)
test:
	sudo nping -c1 --arp google.com
	ping -c1 google.com
	ping -c1 -6 google.com
	sudo nping -c1 --tcp google.com
	nping -c1 --udp google.com
	sudo nping -c1 --tcp -6 google.com
	nping -c1 --udp -6 google.com
	sudo nping  -c1 --tcp -p 80 google.com

clean:
	rm -f $(BIN) $(ARCHIVENAME) 

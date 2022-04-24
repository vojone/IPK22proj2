# IPK21/22 2. project - Packet Sniffer (ZETA variant)

## Author
Vojtěch Dvořák (xdvora3o)

## Files
- `ipk-sniffer.cpp` source code of the project in C++ language
- `Makefile` standard Makefile for this project
- `manual.pdf` detailed description and documentation of this project
- `README.md` this

## About
Simple program written in C++ for catching packets on given network interface. It writes data of packets and its details to stdout. The program ends after it sniffes given amount of packets OR when is CTRL-C pressed (SIGINT is sent). If error occurs, program ends with code 1. Otherwise it returns 0. For more details see `manual.pdf`. Tested on virtual machine with Ubuntu 20.04.02 and compared with Wireshark outputs.

## Library dependencies
iostream, getopt.h, sys/types.h, pcap.h, sys/time.h, arpa/inet.h, stdio.h, ctype.h, iomanip, string, ctime, signal.h

## Usage
Use `make` for compilation. Then the program can be executed by the command in following format (needs sudo):


```
./ipk-sniffer [-i if_name | --interface if_name] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} {--help|-h}
```

- `i` (`interface`) specifies interface, where should be packets catched (compulsory option)
- `n` specifies amount of packets, that should be catched (implicitly set to 1)
- other options specify packet filtering

## Examples

- `sudo ./ipk-sniffer -i enp0s3 -num 100` sniffs 100 packets and it does not matter what their type is

- `sudo ./ipk-sniffer -i enp0s3 -p 80` sniffs only (one) packet, that uses port 80 (as src/dst port)

- `sudo ./ipk-sniffer -i enp0s3 --icmp --arp -p 80` sniffs only (one) packet, that uses port 80 (as src/dst port) or it is ICMP packet or it is ARP packet


## Limits
- it must be executed with `root` privileges
- suppports IPv4, IPv6, ICMP, ICMPv6, UDP, TCP, ARP protocols (other network/transport layer protocols may appear without causing any errors, only headers are not parsed)
- only LINKTYPE_ETHERNET is supported
- IPv6 extension headers are not supported
- IPv4 options can occur, but they are not showed as a "special information" at the output of the program



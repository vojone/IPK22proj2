/******************************************************************************
 *                             IPK - 2. project                               *
 *                                                                            *
 *                              Packet sniffer                                *
 *                                                                            *
 *                      Author: Vojtech Dvorak (xdvora3o)                     *
 *                                                                            *
 * ***************************************************************************/


#include <iostream>
#include <getopt.h>
#include <sys/types.h>
#include <pcap.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#include <iomanip>
#include <string>
#include <ctime>
#include <signal.h>

#define UNSET -1

//Format settings of output
#define SECTION_LEN 8 //After SECTION_LEN bytes is double gap printed

#define LINE_LEN 16 //Maximum amount of bytes from packet in one row

#define UNPRINTABLE_CHAR '.' //Substitution character for unprintable chars


#define MAC_ADDR_SIZE 6 //Size of field with MAC adress in bytes

#define IPV4_ADDR_SIZE 4  //Size of field with IPV4 adress in bytes

#define IPV6_ADDR_SIZE 16  //Size of field with IPV6 adress in bytes

#define T_BUFF_SIZE 128 //Size of temporary buffer for converting timestamp to string


/**
 * @brief Indexes of protocol filtering settings in setting_t structure
 */
typedef enum {
    TCP_INDEX, UDP_INDEX, ARP_INDEX, ICMP_INDEX, PROTO_NUM
} proto_indexes_t;


/**
 * @brief Storage for settings set by user
 */
typedef struct settings {
    char *iname;
    int port_num;
    bool protocols[PROTO_NUM], all_disabled, all_wport_disabled;
    size_t num;
} settings_t;


/**
 * @brief Ether-types of catched frames 
 */
typedef enum { 
    IPV4 = 0x0800, 
    ARP = 0x0806,
    IPV6 = 0x86DD, 
} ether_type_t;

/**
 * @brief Contains fields of ethernet header, sniffer supports only ethernet frames
 * @note By mapping these structurer to sniffed packet, header can be easily parsed
 */
typedef struct eth_frame_hdr {
    const u_char dst_addr[MAC_ADDR_SIZE]; /**< Source address */
    const u_char src_addr[MAC_ADDR_SIZE]; /**< Destination address */
    const u_short type; /**< Type of the frame */
} eth_frame_hdr_t;


/**
 * @brief Enumeration of chosen numbers, that specify transport protocol
 * @note These numbers can be find in proto field (IPv4) or next_header (IPv6)
 * @see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
typedef enum {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMP6 = 58,
} protocol_num_t;


#define IPV4_PROLOG_SIZE 8 //The amount of first bytes in ipv4 header that are not parsed

/**
 * @brief Represents ipv4 header and its fields (implemented according to @see RFC791 )
 * @note For easier parsing of sniffed frame
 */
typedef struct ipv4_hdr {
    const u_char prolog[IPV4_PROLOG_SIZE];
    const u_char ttl;
    const u_char protocol;
    const u_short checksum;
    const u_char src_addr[IPV4_ADDR_SIZE];
    const u_char dst_addr[IPV4_ADDR_SIZE];
} ipv4_hdr_t;


#define IPV6_PROLOG_SIZE 6 //The amount of first bytes in ipv6 header that are not parsed
 
/**
 * @brief Represents ipv6 header and its fields ( @see RFC 2460 )
 */
typedef struct ipv6_hdr {
    const u_char prolog[IPV6_PROLOG_SIZE];
    const u_char next_hdr; /**< Next header field */
    const u_char max_hops;
    const u_char src_addr[IPV6_ADDR_SIZE];
    const u_char dst_addr[IPV6_ADDR_SIZE];
} ipv6_hdr_t;


/**
 * @brief Contains all important fields of TCP header ( @see RFC 793 ) 
 */
typedef struct tcp_hdr {
    const u_short src_port;
    const u_short dst_port;
    const u_char* rest;
} tcp_hdr_t;

/**
 * @brief Contains all important field of UDP header ( @see RFC 768 ) 
 */
typedef struct udp_hdr {
    const u_short src_port;
    const u_short dst_port;
    const u_char* rest;
} udp_hdr_t;


/**
 * @brief Correctly frees all resources held by given pointer, sort of garbage collecting function
 * @param reg_mode If it is true, function is in registration mode - it save given pointers
 * @param ifs Pointer to interface list
 * @param pcap_ptr Pointer to pcap structure
 */
void free_resources(bool reg_mode, pcap_if_t *ifs, pcap_t *pcap_ptr) {
    static pcap_if_t *interfaces = NULL;
    static pcap_t *pcap = NULL;

    if(reg_mode) {
        interfaces = ifs;
        pcap = pcap_ptr;
    }
    else {
        if(interfaces) {
            pcap_freealldevs(interfaces);
        }

        if(pcap) {
            pcap_close(pcap);
        }
    }
}


/**
 * @brief Get pointer to first element of linked list with interfaces
 * @todo It should get only active interfaces
 * @param interfaces Pointer to pointer, that will be filled with address of first interface structure
 * @param error_buff Pointer to error buffer to store error msg
 * @return int EXIT_SUCCESS or EXIT_FAILURE
 */
int get_interfaces(pcap_if_t **interfaces, char *error_buff) {

    if(pcap_findalldevs(interfaces, error_buff) < 0) {
        std::cerr << "Error: " << error_buff << std::endl;
        return EXIT_FAILURE;
    }

    free_resources(true, *interfaces, NULL); /**< Adding pointer to interface list to garbage collection function */
    
    return EXIT_SUCCESS;
}


/**
 * @brief Prints list of the names of interfaces from argument to standard error output
 * @param interfaces Pointer to first element of linked with interfaces
 */
void print_all_interfaces(pcap_if_t *interfaces) {
    pcap_if_t *current;

    std::cerr << std::endl;

    for(current = interfaces; current; current = current->next) {
        std::cerr << current->name;
        std::cerr << std::endl;
    }

    std::cerr << std::endl;
}


/**
 * @brief Frees resources to minimize memory leaks and then ends program with given code
 * @param exit_code With this code will be program ended
 */
void safe_exit(int exit_code) {
    free_resources(false, NULL, NULL);

    exit(exit_code);
}


/**
 * @brief Prints list with all interfaces and end program with EXIT_FAILURE code
 * @param interfaces Linked list with interfaces to be printed
 */
void bad_interface_abort(pcap_if_t *interfaces) {
    print_all_interfaces(interfaces);

    safe_exit(EXIT_FAILURE);
}


/**
 * @brief Get the port number as unsigned integer from string
 * @note If the format of argument to be converted is invalid, program is ended with error code EXIT_FAILURE
 * @param port_num_param String to be converted to port number
 * @return unsigned int Port number (readable by human)
 */
unsigned int get_port_number(char *port_num_param) {
    char *rest = NULL;
    int port_num = strtol(port_num_param, &rest, 10);
    if(*rest != '\0') {
        std::cerr << "Invalid parameter of -p option (port number)!" <<  std::endl;
        safe_exit(EXIT_FAILURE);
    }

    if(port_num < 0 || port_num > 65536) {
        std::cerr << "Parameter of -p option must be valid port number!" << std::endl;
        safe_exit(EXIT_FAILURE);
    }

    return (unsigned int)port_num;
}


/**
 * @brief Converts string parameter of the program to unsigned integer
 * @note If value in string is invalid, program is ended with exit code EXIT_FAILURE
 * @param number_param String to be converted
 * @return unsigned int Converted value
 */
unsigned int get_number_opt(char *number_param) {
    char *rest = NULL;
    int num = strtoul(number_param, &rest, 10);
    if(*rest != '\0') {
        std::cerr << "Invalid parameter of -n option!" << std::endl;
        safe_exit(EXIT_FAILURE);
    }

    if(num < 0) {
        std::cerr << "Parameter of -n option must be positive integer!" << std::endl;
        safe_exit(EXIT_FAILURE);
    }

    return num;
}


/**
 * @brief Initializes structure with settings to default state
 * @param settings 
 */
void init_settings(settings_t *settings) {
    settings->iname = NULL;
    settings->port_num = UNSET;
    settings->num = 1;

    for(size_t i = 0; i < PROTO_NUM; i++) {
        settings->protocols[i] = false;
    }

    settings->all_disabled = true;
    settings->all_wport_disabled = true;
}


/**
 * @brief Prints error msg (as a reaction to unrecognized argument of program) and ends program with EXIT_FAILURE 
 * @param argv Argv array from main function
 * @param interfaces Linked list with active interfaces (to print messages properly)
 */
void unrecognized_option_abort(char** argv, pcap_if_t *interfaces) {
    const char * option = argv[optind-1];

    if(optopt == 'i') {
        std::cerr << "Missing param of interface specifier!" << std::endl;
        bad_interface_abort(interfaces);
    }
    else if(optopt == 'n' || optopt == 'p') {
        std::cerr << "Parameter is required after " << option << std::endl;
    }
    else {
        std::cerr << "Unrecognized option: " << option <<  std::endl;
    }

    safe_exit(EXIT_FAILURE);
}


/**
 * @brief Updates general parts of setting structure (due to other setting fields in this structure)
 * @param settings Structure to be updated
 */
void update_general_settings(settings_t *settings) {
    settings->all_disabled = true;
    settings->all_wport_disabled = true;

    for(size_t i = 0; i < PROTO_NUM; i++) {
        if(settings->protocols[i]) {
            settings->all_disabled = false;

            if(i == TCP_INDEX || i == UDP_INDEX) {
                settings->all_wport_disabled = false;
            }
        }
    }
}


/**
 * @brief Chooses action due to parsed argument of program (parsed by getopt_long)
 *        typicaly, it modifies settings structure
 * @param opt Return value of getopt_long
 * @param argv Argument vector from main function
 * @param sets Setting structure
 * @param ifs Linked list with interfaces
 * @note If unrecognized option is found program is ended by calling unrecognized_option_abort
 */
void resolve_option(int opt, char** argv, settings_t *sets, pcap_if_t *ifs) {
    switch (opt)
    {
    case 'i':
        sets->iname = optarg; /**< Chosen interface */
        break;
        
    case 'p': 
        sets->port_num = get_port_number(optarg); /**< Filtering by port number is activated */
        break;

    case 'n':
        sets->num = get_number_opt(optarg); /**< Number of packets is set */
        break;

    //Protocol filtering
    case 't':
        sets->protocols[TCP_INDEX] = true;
        break;

    case 'u':
        sets->protocols[UDP_INDEX] = true;
        break;

    case 'a':
        sets->protocols[ARP_INDEX] = true;
        break;

    case '$':
        sets->protocols[ICMP_INDEX] = true;
        break;

    default:
        unrecognized_option_abort(argv, ifs);
    }

    update_general_settings(sets); /**< Update all_disabled and udp_and_tcp_disabled */
}

/**
 * @brief Parses options (or arguments) of program (uses getopt_long function)
 * @param argc Argument count (from main)
 * @param argv Argument vector (from main)
 * @param settings Settings structure, that should be modified
 * @param ifs Pointer to linked list with interfaces
 */
void parse_ops(int argc, char** argv, settings_t *settings, pcap_if_t *ifs) {
    //Accepted long options
    const static option l_opts[] = {
        {"interface", required_argument, NULL, 'i'},
        {"tcp", no_argument, NULL, 't'},
        {"udp", no_argument, NULL, 'u'},
        {"arp", no_argument, NULL, 'a'},
        {"icmp", no_argument, NULL, '$'},
        {0, 0, NULL, 0}
    };

    //Accepted short options
    const static char *s_opts = "i:p:tun:";

    opterr = 0;
    int opt, opt_index;
    while((opt = getopt_long(argc, argv, s_opts, l_opts, &opt_index)) >= 0) {
        resolve_option(opt, argv, settings, ifs);
    }

    //Check if interface name was given (its validity is checked elsewhere)
    if(!settings->iname) {
        std::cerr << "Network interface must be specified!" << std::endl;
        bad_interface_abort(ifs);
    }
}


/**
 * @brief Prints given integer in hexadecimal format to std output
 * @param num Integer to be printed
 * @param wprefix If it is true, prefix '0x' is prepended
 * @param b_size Size of number in bytes (unused halfbytes will be filled with zeros)
 */
void print_as_hex(int num, bool wprefix, size_t b_size) {

    if(wprefix) {
        std::cout << "0x";
    }

    std::cout << std::setfill('0') << std::setw(b_size*2) << std::hex << num;
    std::cout << std::dec; //Setting output to normal mode
}


/**
 * @brief Returns gap to be printed between bytes of the frame
 *        (format specified in assigment contains double space 
 *         between each SECTION_LEN and SECTION_LEN + 1 byte)
 * @param i Index of byte
 * @param long_gap Long version of gap, is used only for (SECTION_LEN + 1)th byte
 * @param short_gap Normal gap
 * @return const char Chosen gap
 */
const char* choose_gap(size_t i, const char* long_gap, const char* short_gap) {
    return ((i + 1) % SECTION_LEN == 0) ? long_gap : short_gap;
}


/**
 * @brief Prints padding (whitespaces) after end of last line of frame
 * @note Used to make ouput more beautiful
 * @param cur_byte Offset of last printed byte (the last byte of frame)
 */
void print_padding(size_t cur_byte) {
    while(cur_byte % LINE_LEN != 0) {
        std::cout << "  "; //Instead of byte

        std::cout << choose_gap(cur_byte, "  ", " ");

        cur_byte++;
    }
}


/**
 * @brief Prints line of the frame as characters (unprintable ones are substituted for UNPRINTABLE_CHAR)
 * @param pkt Frame (packet) to be printed
 * @param line_cnt Number of printed bytes in one row
 * @param cur_byte Offset of last printed byte (in hexa representation)
 */
void print_line_as_chars(const u_char *pkt, size_t line_cnt, size_t cur_byte) {
    for(size_t i = cur_byte - line_cnt; i < cur_byte; i++) {
        if(!isprint(pkt[i])) {
            std::cout << UNPRINTABLE_CHAR;
        }
        else {
            std::cout << pkt[i];
        }

        std::cout << choose_gap(i, " ", "");
    }
}


/**
 * @brief Fills given structure with information included in packet (it does something like "parsing")
 * @tparam HDR_TYPE Type (structure), that contains all fields specified by standards
 * @param start Start index, that specifies, where header starts
 * @param len Total length of sniffed frame
 * @param frame Pointer to array with sniffed frame
 * @param hdr Pointer to pointer to structure, that should be filled
 * @return true Parsing if probably done correctly (depends on start index and used structure)
 * @return false There are not enough bytes to fill the structure (probably bad structure was chosen)
 * 
 * IMPORTANT: The idea of mapping structure to the packet for easier parsing was taken from 
 */
template <typename HDR_TYPE>
bool get_hdr(size_t *start, size_t len, const u_char *frame, HDR_TYPE **hdr) {
    if(len - (*start) < sizeof(HDR_TYPE) || len <= *start || *start < 0) {
        return false;
    }

    *hdr = (HDR_TYPE *)(&(frame[*start]));
    *start += sizeof(HDR_TYPE);

    return true;
}



/**
 * @brief Prints MAC address in typical format (xx:xx:xx:xx:xx:xx) including newline
 * @param addr Pointer to adress (array of bytes), that should be printed
 */
void print_mac_addr(const u_char *addr) {
    for(size_t i = 0; i < MAC_ADDR_SIZE; i++) {
        if(i > 0) {
            std::cout << ":";
        }

        print_as_hex(addr[i], false, sizeof(char));
    }

    std::cout << std::endl;
}


/**
 * @brief Prints IPv4 adress as it is typical (d.d.d.d)
 * @param addr Pointer to adress (array of bytes), that should be printed
 */
void print_ipv4_addr(const u_char *addr) {
    for(size_t i = 0; i < IPV4_ADDR_SIZE; i++) {
        if(i > 0) {
            std::cout << ".";
        }

        std::cout << +addr[i];
    }

    std::cout << std::endl;
}


/**
 * @brief Prints IPv6 adress according to one of possible formats specified in RFC 4291
 * @param addr Adress to be printed (array of bytes)
 */
void print_ipv6_addr(const u_char *addr) {
    for(size_t i = 0; i < IPV6_ADDR_SIZE; i++) {
        if(i > 0 && i % 2 == 0) {
            std::cout << ":";
        }

        if(i < IPV6_ADDR_SIZE - 1 && addr[i] == 0 && addr[i + 1] == 0) {
            std::cout << "0";
            i++;
        }
        else {
            print_as_hex(addr[i], false, sizeof(char));
        }
    }

    std::cout << std::endl;
}


/**
 * @brief Prints genera information about the ethernet frame
 * @param pkt_header Pointer to structure with frame header information
 * @param eth_hdr Pointer to structure with information about the frame
 */
void print_header_info(pcap_pkthdr *pkt_header, eth_frame_hdr_t *eth_hdr) {
    char ts_buffer[T_BUFF_SIZE];
    std::tm gtime_buffer;

    //Formatting of timestamp (it is formatted according to RFC3339)
    std::tm *gtime = gmtime(&(pkt_header->ts.tv_sec));
    gtime_buffer = *gtime;
    std::tm *ltime = localtime(&(pkt_header->ts.tv_sec));

    std::strftime(ts_buffer, T_BUFF_SIZE, "%Y-%m-%dT%H:%M:%S", ltime);
    std::cout << "timestamp: " << std::dec << ts_buffer;

    short t_offset = ltime->tm_hour - gtime_buffer.tm_hour;
    std::string usec_str(std::to_string(pkt_header->ts.tv_usec/(double)1e6));
    usec_str.erase(0, 1); /**< Removing 0 from start (it always be in format 0. ...) */
    
    snprintf(ts_buffer, T_BUFF_SIZE, "%s%+d:00", usec_str.c_str(), t_offset);
    std::cout << ts_buffer << std::endl;

    //Printing adresses
    std::cout << "src MAC: ";
    print_mac_addr(eth_hdr->src_addr);

    std::cout << "dst MAC: ";
    print_mac_addr(eth_hdr->dst_addr);

    std::cout << "frame len: " << std::dec << pkt_header->len << std::endl;

    //Additional information about ethertype
    std::cout << "ethertype.: "; //TODO
    print_as_hex(ntohs(eth_hdr->type), true, sizeof(short));
    std::cout << std::endl;
}


/**
 * @brief Converts setting with specified protocol filter to corresponding filter string
 * @param filter_str Output string
 * @param settings Structure to be converted (typicaly got by parsing of arguments)
 * @param i Index of protocol in setting structure array
 */
void setting_to_str(std::string *filter_str, settings_t *settings, size_t i) {
    bool recognized = true;
    bool is_udp_or_tcp = i == TCP_INDEX || i == UDP_INDEX;
    bool port_active = settings->port_num != UNSET;
    if(settings->protocols[i]) {
        if(!filter_str->empty()) {
            filter_str->append("or ");
        }

        filter_str->append("(");

        switch (i)
        {
        case ARP_INDEX:
            filter_str->append("arp ");
            break;
        case ICMP_INDEX:
            filter_str->append("icmp or icmp6 ");
            break;
        case TCP_INDEX:
            filter_str->append("tcp ");
            break;
        case UDP_INDEX:
            filter_str->append("udp ");
            break;
        default:
            recognized = false;
            filter_str->erase(filter_str->length() - 1, 1);
            break;
        }

        if(recognized) {
            if(is_udp_or_tcp && port_active) {
                filter_str->append("and port ");
                filter_str->append(std::to_string(settings->port_num));
            }

            filter_str->append(") ");
        }
    }
}


/**
 * @brief Converts setting structure to string containing filter to be compiled with pcap library
 * @param filter_str Ouput string, that is erased and filled with filter
 * @param settings Structure to be converted (typicaly got by parsing of arguments)
 * 
 * IMPORTANT: The know how of creation of "filter strings" was taken from man pages of pcap-filter (7) 
 */
void create_filter_str(std::string *filter_str, settings_t *settings) {
    filter_str->clear();

    if(settings->all_disabled && settings->port_num == UNSET) {
        return;
    }

    for(size_t i = 0; i < PROTO_NUM; i++) {
        setting_to_str(filter_str, settings, i);
    }

    if(settings->all_wport_disabled && settings->port_num != UNSET) {
        if(!filter_str->empty()) {
            filter_str->append("or ");
        }

        filter_str->append("port ");
        filter_str->append(std::to_string(settings->port_num));
    }
}


/**
 * @brief Prints all bytes of frame in form that is required by assignment
 * @param pkt_header Header of the sniffed frame
 * @param pkt Pointer to content of the frame
 */
void dump_pkt(pcap_pkthdr *pkt_header, const u_char *pkt) {
    size_t i = 0, line_cnt = i;
    for(; i < pkt_header->caplen; i++, line_cnt++) {
        if(line_cnt % LINE_LEN == 0) {
            if(i > 0) {
                print_line_as_chars(pkt, line_cnt, i); /**< After each line, bytes are printed in ASCII */
                line_cnt = 0;
                std::cout << std::endl;
            }

            print_as_hex((int)i, true, sizeof(short)); /**< Printing bytes as hex */
            std::cout << ":  ";
        }

        print_as_hex(pkt[i], false, sizeof(char));

        const char *gap = ((i + 1) % SECTION_LEN == 0) ? "  " : " ";
        std::cout << gap;
    }

    print_padding(i);
    print_line_as_chars(pkt, line_cnt, i);

    std::cout << std::endl;
    std::cout << std::endl;
}


/**
 * @brief Converts port_number to human readability representation (through ntohs)
 *        and prints it to stdout with newline at the end
 * @param port_num Port number (netshort) to be converted
 */
void print_port(const u_short port_num) {
    std::cout << std::dec << ntohs(port_num) << std::endl;
}


/**
 * @brief Prints details included in IPv4 header and optionally in other headers of higher layers
 * @param start_index Index where IPv4 header should start
 * @param flen Frame length
 * @param pkt Pointer to arra with frame content
 */
void print_ipv4_details(size_t *start_index, size_t flen, const u_char *pkt) {
    ipv4_hdr_t *ipv4_header;

    if(get_hdr<ipv4_hdr_t>(start_index, flen, pkt, &ipv4_header)) {
        std::cout << "ipv4 protocol: "; //TODO
        print_as_hex(ipv4_header->protocol, false, sizeof(char));
        std::cout << std::endl;

        std::cout << std::dec << "src IP: ";
        print_ipv4_addr(ipv4_header->src_addr);

        std::cout << std::dec << "dst IP: ";
        print_ipv4_addr(ipv4_header->dst_addr);

        //Higher layers
        if(ipv4_header->protocol == TCP) {
            tcp_hdr_t *tcp_header;

            if(get_hdr<tcp_hdr_t>(start_index, flen, pkt, &tcp_header)) {
                std::cout << "src port: ";
                print_port(tcp_header->src_port);

                std::cout << "dst port: ";
                print_port(tcp_header->dst_port);
            }
        }
        else if(ipv4_header->protocol == UDP) {
            udp_hdr_t *udp_header;

            if(get_hdr<udp_hdr_t>(start_index, flen, pkt, &udp_header)) {
                std::cout << "src port: ";
                print_port(udp_header->src_port);

                std::cout << "dst port: ";
                print_port(udp_header->dst_port);
            }
        }
    }
}


/**
 * @brief Prints details included in IPv6 header and optionally in other headers of higher layers
 * @param start_index Index where IPv6 header should start
 * @param flen Frame length
 * @param pkt Pointer to arra with frame content
 */
void print_ipv6_details(size_t *start_index, size_t flen, const u_char *pkt) {
    ipv6_hdr_t *ipv6_header;

    if(get_hdr<ipv6_hdr_t>(start_index, flen, pkt, &ipv6_header)) {
        std::cout << "ipv6 protocol: "; //TODO
        print_as_hex(ipv6_header->next_hdr, false, sizeof(char));
        std::cout << std::endl;

        std::cout << std::dec << "src IP: ";
        print_ipv6_addr(ipv6_header->src_addr);

        std::cout << std::dec << "dst IP: ";
        print_ipv6_addr(ipv6_header->dst_addr);

        //Higher layers
        if(ipv6_header->next_hdr == TCP) {
            tcp_hdr_t *tcp_header;

            if(get_hdr<tcp_hdr_t>(start_index, flen, pkt, &tcp_header)) {
                std::cout << "src port: ";
                print_port(tcp_header->src_port);

                std::cout << "dst port: ";
                print_port(tcp_header->dst_port);
            }
        }
        else if(ipv6_header->next_hdr == UDP) {
            udp_hdr_t *udp_header;

            if(get_hdr<udp_hdr_t>(start_index, flen, pkt, &udp_header)) {
                std::cout << "src port: ";
                print_port(udp_header->src_port);

                std::cout << "dst port: ";
                print_port(udp_header->dst_port);
            }
        }
    }
}


/**
 * @brief Performs packet (frame) sniffing itself
 * @param pcap_ptr Pointer to intialized pcap structure
 */
void sniff_packet(pcap_t *pcap_ptr) {
    const u_char *pkt;
    pcap_pkthdr pkt_header;

    pkt = pcap_next(pcap_ptr, &pkt_header);
    //std::cout << pkt_header.len << "\n";

    eth_frame_hdr_t *eth_hdr;

    size_t start_index = 0;
    size_t frame_len = pkt_header.caplen;
    
    //Print details contained in headers
    if(get_hdr<eth_frame_hdr_t>(&start_index, frame_len, pkt, &eth_hdr)) {
        print_header_info(&pkt_header, eth_hdr);

        u_short ether_type = ntohs(eth_hdr->type);
        if(ether_type == IPV4) {
            print_ipv4_details(&start_index, frame_len, pkt);
        }
        else if(ether_type == IPV6) {
            print_ipv6_details(&start_index, frame_len, pkt);
        }
    }   

    dump_pkt(&pkt_header, pkt);
}


/**
 * @brief Handler for unexpected termination by SIGINT signal
 * @param signal_number 
 */
void termination_handler(int signal_number) {
    (void)signal_number;

    free_resources(false, NULL, NULL); /**< Correctly frees all registered resources */

    exit(EXIT_SUCCESS);
}


/**
 * @brief Initializes pcap structure to be used (including compiling and setting filter)
 * @param pcap_ptr Pointer to pointer to pcap structure that will be filled with the adress of initialized pcap 
 * @param settings Setting structure (from argument parsing)
 * @param err_buff Buffer for error messaged
 * @param interfaces Pointer to linked list with interfaces
 * @note If any part of initialization is not succesfull, program is ended and error msg is printed
 * 
 * IMPORTANT: The way how is pcap handle (pcap_ptr) initialized was taken from https://www.tcpdump.org/pcap.html
 */
void init_pcap(pcap_t **pcap_ptr, settings_t *settings, 
               char *err_buff, pcap_if_t *interfaces) {

    *pcap_ptr = NULL;

    bpf_u_int32 mask;
    bpf_u_int32 net;
    bpf_program filter;

    //Preparing of pcap_t structure is made due to pcap.h man pages
    if(pcap_lookupnet(settings->iname, &net, &mask, err_buff) < 0) {
        std::cerr << "Unable to find '" << settings->iname << "'! ";
        std::cerr << err_buff << std::endl;
        bad_interface_abort(interfaces);
    }

    //Setting the "wise" timeout (1s) to prevent waking up too oftenly
    *pcap_ptr = pcap_open_live(settings->iname, BUFSIZ, 
                               PCAP_OPENFLAG_PROMISCUOUS, 1000,
                               err_buff);
    if(!(*pcap_ptr)) {
        std::cerr << "Error while opening: " << err_buff << std::endl;
        safe_exit(EXIT_FAILURE);
    }

    //Register resources (pcap handle) to free it when program is terminated
    free_resources(true, interfaces, *pcap_ptr);

    //Filter creation
    std::string filter_str;
    create_filter_str(&filter_str, settings);
    //std::cout << filter_str << std::endl << std::flush;

    if(pcap_compile(*pcap_ptr, &filter, filter_str.c_str(), 0, net) < 0) {
        std::cerr << "Error while compiling filter! ";
        std::cerr << pcap_geterr(*pcap_ptr) << std::endl;
        safe_exit(EXIT_FAILURE);
    }

    if(pcap_setfilter(*pcap_ptr, &filter) < 0) {
        std::cerr << "Error while setting filter! ";
        std::cerr << pcap_geterr(*pcap_ptr) << std::endl;
        safe_exit(EXIT_FAILURE);
    }
}


int main(int argc, char* argv[]) {
    signal(SIGINT, termination_handler);

    char err_buff[PCAP_ERRBUF_SIZE]; /**< Buffer for error messages (required by pcap functions) */

    settings_t settings;
    init_settings(&settings);

    pcap_if_t *interfaces = NULL;
    if(get_interfaces(&interfaces, err_buff)) {
        safe_exit(EXIT_FAILURE);
    }

    parse_ops(argc, argv, &settings, interfaces);

    pcap_t *pcap_ptr;
    
    init_pcap(&pcap_ptr, &settings, err_buff, interfaces);

    for(int frame_cnt = 0; true; frame_cnt++) { //TODO
        sniff_packet(pcap_ptr);
    }

    safe_exit(EXIT_SUCCESS);
}
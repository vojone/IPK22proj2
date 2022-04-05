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

#define UNSET -1

//Format settings of output
#define SECTION_LEN 8 //After SECTION_LEN bytes is double gap printed

#define LINE_LEN 16 //Maximum amount of bytes from packet in one row

#define UNPRINTABLE_CHAR '.' //Substitution character for unprintable chars


#define DST_MAC_SIZE 6 //Size of field with DST MAC adress in sniffed frame

#define SRC_MAC_SIZE 6 //Size of field with SRC MAC adress in sniffed frame


#define T_BUFF_SIZE 128 //Size of temporary buffer for converting timestamp to string


/**
 * @brief Ether types of catched frames
 */
typedef enum { 
    OTHER = 0x0000, 
    IPV4 = 0x0800, 
    ARP = 0x0806,
    IPV6 = 0x86DD, 
} 
ether_type_t;


/**
 * @brief Indexes of protocol filtering settings in setting_t structure
 */
typedef enum {
    TCP_INDEX, UDP_INDEX, ARP_INDEX, ICMP_INDEX, PROTO_NUM
}
proto_indexes_t;


/**
 * @brief Storage for settings set by user
 */
typedef struct settings {
    char *iname;
    int port_num;
    bool protocols[PROTO_NUM], all_disabled, udp_and_tcp_disabled;
    size_t num;
} settings_t;


/**
 * @brief Structure holds general info about catched frame
 */
typedef struct frame_info {
    u_char dst_addr[DST_MAC_SIZE]; /**< Source address */
    u_char src_addr[SRC_MAC_SIZE]; /**< Destination address */
    ushort type; /**< Type of the frame */
} frame_info_t;


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
    
    return EXIT_SUCCESS;
}


/**
 * @brief Prints list of the names of interfaces from argument to standard error output
 * @param interfaces Pointer to first element of linked with interfaces
 */
void print_all_interfaces(pcap_if_t *interfaces) {
    pcap_if_t *current;

    for(current = interfaces; current; current = current->next) {
        std::cerr << current->name << "  ";
    }

    std::cerr << std::endl;
}


/**
 * @brief Prints list with all interfaces and end program with EXIT_FAILURE code
 * @param interfaces Linked list with interfaces to be printed
 */
void bad_interface_abort(pcap_if_t *interfaces) {
    std::cerr << "Active interfaces: " << std::endl;

    print_all_interfaces(interfaces);

    exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }

    if(port_num < 0 || port_num > 65536) {
        std::cerr << "Parameter of -p option must be valid port number!" << std::endl;
        exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }

    if(num < 0) {
        std::cerr << "Parameter of -n option must be positive integer!" << std::endl;
        exit(EXIT_FAILURE);
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
    settings->udp_and_tcp_disabled = true;
}


/**
 * @brief Prints error msg (as a reaction to unrecognized argument of program) and ends program with EXIT_FAILURE 
 * @param argv Argv array from main function
 * @param interfaces Linked list with active interfaces (to print messages properly)
 */
void unrecognized_option_abort(char** argv, pcap_if_t *interfaces) {
    if(optopt == 'i') {
        std::cerr << "Missing param of interface specifier!" << std::endl;
        bad_interface_abort(interfaces);
    }
    else if(optopt == 'n' || optopt == 'p') {
        std::cerr << "Parameter is required after!" << argv[optind-1] <<  std::endl;
    }
    else {
        std::cerr << "Unrecognized option: " << argv[optind-1] <<  std::endl;
    }

    exit(EXIT_FAILURE);
}


/**
 * @brief Updates general parts of setting structure (due to other setting fields in this structure)
 * @param settings Structure to be updated
 */
void update_general_settings(settings_t *settings) {
    settings->all_disabled = true;
    settings->udp_and_tcp_disabled = true;

    for(size_t i = 0; i < PROTO_NUM; i++) {
        if(settings->protocols[i]) {
            settings->all_disabled = false;

            if(i == TCP_INDEX || i == UDP_INDEX) {
                settings->udp_and_tcp_disabled = false;
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
const char* choose_gap(uint i, const char* long_gap, const char* short_gap) {
    return ((i + 1) % SECTION_LEN == 0) ? long_gap : short_gap;
}


/**
 * @brief Prints padding (whitespaces) after end of last line of frame
 * @note Used to make ouput more beautiful
 * @param cur_byte Offset of last printed byte (the last byte of frame)
 */
void print_padding(uint cur_byte) {
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
void print_line_as_chars(const u_char *pkt, uint line_cnt, uint cur_byte) {
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
 * @brief Fills frame info structure with information about the frame
 * @note Supports only ethernet packets
 * @param pkt Frame (packet) with information
 * @param info Pointer to structure, that should be filled
 */
void get_frame_info(const u_char *pkt, frame_info_t *info) {
    for(size_t i = 0; i < DST_MAC_SIZE; i++) {
        info->dst_addr[i] = pkt[i];
    }


    for(size_t i = 0; i < SRC_MAC_SIZE; i++) {
        info->src_addr[i] = pkt[i + SRC_MAC_SIZE];
    }

    //Converting EtherType to readable representation
    info->type = ntohs((short)pkt[DST_MAC_SIZE + SRC_MAC_SIZE]);
}

/**
 * @brief Prints general (interesting) information about the frame (packet)
 * @param pkt_header Pointer to structure with frame header information
 * @param info Pointer to structure with information about the frame
 */
void print_header_info(pcap_pkthdr *pkt_header, frame_info_t *info) {
    char ts_buffer[T_BUFF_SIZE];
    std::tm gtime_buffer;

    std::tm *gtime = gmtime(&(pkt_header->ts.tv_sec));
    gtime_buffer = *gtime;
    std::tm *ltime = localtime(&(pkt_header->ts.tv_sec));
    std::strftime(ts_buffer, T_BUFF_SIZE, "%Y-%m-%dT%H:%M:%S", ltime);

    std::cout << "ts: " << std::dec << ts_buffer;

    short t_offset = ltime->tm_hour - gtime_buffer.tm_hour;
    snprintf(ts_buffer, T_BUFF_SIZE, ".%ld%+d:00", pkt_header->ts.tv_usec, t_offset);

    std::cout << ts_buffer << std::endl;


    std::cout << "len: " << std::dec << pkt_header->len << std::endl;


    std::cout << "dst.: ";
    for(size_t i = 0; i < 6; i++) {
        print_as_hex(info->dst_addr[i], false, sizeof(char));
    }

    std::cout << std::endl;


    std::cout << "src.: ";
    for(size_t i = 0; i < 6; i++) {
        print_as_hex(info->src_addr[i], false, sizeof(char));
    }
    std::cout << std::endl;


    std::cout << "type.: ";
    print_as_hex(info->type, false, sizeof(short));
    std::cout << std::endl;
}


void setting_to_str(std::string *filter_str, settings_t *settings, size_t i) {
    bool recognized = true;

    bool is_udp_or_tcp = i == TCP_INDEX || i == UDP_INDEX;
    bool port_active = settings->port_num != UNSET;
    bool all_transp_disabled = settings->udp_and_tcp_disabled;
    bool uni_port_filter = is_udp_or_tcp && port_active && all_transp_disabled;

    if(settings->protocols[i] || uni_port_filter) {
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
            filter_str->append("icmp ");
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


void create_filter_str(std::string *filter_str, settings_t *settings) {
    filter_str->clear();

    if(settings->all_disabled && settings->port_num == UNSET) {
        return;
    }

    for(size_t i = 0; i < PROTO_NUM; i++) {
        setting_to_str(filter_str, settings, i);
    }
}


void sniff_packet(pcap_t *pcap_ptr) {
    const u_char *pkt;
    pcap_pkthdr pkt_header;

    pkt = pcap_next(pcap_ptr, &pkt_header);
    //std::cout << pkt_header.len << "\n";

    frame_info_t info;

    get_frame_info(pkt, &info);

    print_header_info(&pkt_header, &info);
    
    uint i = 0, line_cnt = i;
    for(; i < pkt_header.len; i++, line_cnt++) {
        if(line_cnt % LINE_LEN == 0) {
            if(i > 0) {
                print_line_as_chars(pkt, line_cnt, i);
                line_cnt = 0;
                std::cout << std::endl;
            }

            print_as_hex((int)i, true, sizeof(short));
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


int main(int argc, char* argv[]) {
    settings_t settings;
    init_settings(&settings);

    char err_buff[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces = NULL;

    if(get_interfaces(&interfaces, err_buff)) {
        return EXIT_FAILURE;
    }

    parse_ops(argc, argv, &settings, interfaces);

    bpf_u_int32 mask;
    bpf_u_int32 net;
    bpf_program filter;

    //Preparing of pcap_t structure is made due to pcap.h man pages
    if(pcap_lookupnet(settings.iname, &net, &mask, err_buff) < 0) {
        std::cerr << "Unable to find '" << settings.iname << "'! ";
        std::cerr << err_buff << std::endl;
        bad_interface_abort(interfaces);
    }

    pcap_t *pcap_ptr = pcap_open_live(settings.iname, BUFSIZ, 
                                      PCAP_OPENFLAG_PROMISCUOUS, 1000, 
                                      err_buff);

    if(!pcap_ptr) {
        std::cerr << "Error while opening: " << err_buff << std::endl;
        return EXIT_FAILURE;
    }

    std::string filter_str;
    create_filter_str(&filter_str, &settings);
    //std::cout << filter_str << std::endl << std::flush;

    if(pcap_compile(pcap_ptr, &filter, filter_str.c_str(), 0, net) < 0) {
        std::cerr << "Error while compiling filter! ";
        std::cerr << pcap_geterr(pcap_ptr) << std::endl;
        return EXIT_FAILURE;
    }

    if(pcap_setfilter(pcap_ptr, &filter) < 0) {
        std::cerr << "Error while setting filter! ";
        std::cerr << pcap_geterr(pcap_ptr) << std::endl;
        return EXIT_FAILURE;
    }

    for(int pkt_cnt = 0; true; pkt_cnt++) { //TODO
        sniff_packet(pcap_ptr);
    }

    pcap_close(pcap_ptr);

    return EXIT_SUCCESS;
}
#include <iostream>
#include <getopt.h>
#include <cstring>
#include <sys/types.h>
#include <pcap.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#include  <iomanip>
#include <ctime>

#define UNSET -1
#define SNAPLEN 65536

#define SECTION_LEN 8
#define LINE_LEN 16
#define UNPRINTABLE_CHAR '.'


typedef enum { 
    OTHER = 0x0000, 
    IPV4 = 0x0800, 
    ARP = 0x0806,
    IPV6 = 0x86DD, 
} 
ether_type_t;

typedef struct settings {
    char *iname;
    int port_num;
    bool tcp, udp, arp, icmp;
    int num;
} settings_t;

typedef struct frame_info {
    u_char dst_addr[6];
    u_char src_addr[6];
    u_char type[2];
} frame_info_t;


int get_interfaces(pcap_if_t **interfaces, char *error_buff) {

    if(pcap_findalldevs(interfaces, error_buff) < 0) {
        std::cout << "Error: " << error_buff << std::endl;
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

void print_all_interfaces(pcap_if_t *interfaces) {
    pcap_if_t *current;

    for(current = interfaces; current; current = current->next) {
        std::cout << current->name << "  ";
    }

    std::cout << std::endl;
}

void bad_interface_opt(pcap_if_t *interfaces) {
    std::cout << "Active interfaces: " << std::endl;

    print_all_interfaces(interfaces);

    exit(EXIT_FAILURE);
}

unsigned int get_port_number(char *port_num_param) {
    char *rest = NULL;
    int port_num = strtoul(port_num_param, &rest, 10);
    if(strlen(rest) > 0) {
        std::cout << "Invalid parameter of -p option (port number)!" <<  std::endl;
        exit(EXIT_FAILURE);
    }

    if(port_num < 0 || port_num > 65536) {
        std::cout << "Parameter of -p option must be valid port number!" << std::endl;
        exit(EXIT_FAILURE);
    }

    return (unsigned int)port_num;
}

unsigned int get_number_opt(char *number_param) {
    char *rest = NULL;
    int num = strtoul(number_param, &rest, 10);
    if(strlen(rest) > 0) {
        std::cout << "Invalid parameter of -n option!" << std::endl;
        exit(EXIT_FAILURE);
    }

    if(num < 0) {
        std::cout << "Parameter of -n option must be positive integer!" << std::endl;
    }

    return num;
}

void init_settings(settings_t *settings) {
    settings->iname = NULL;
    settings->port_num = UNSET;
    settings->num = 1;
    settings->tcp = false;
    settings->udp = false;
    settings->arp = false;
    settings->icmp = false;
}

int parse_ops(int argc, char** argv, settings_t *settings, pcap_if_t *ifs) {
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
        switch (opt)
        {
        case 'i':
            settings->iname = optarg; 
            break;
        case 'p': 
            settings->port_num = htons(get_port_number(optarg));
            break;
        case 'n':
            settings->num = get_number_opt(optarg);
            break;
        case 't':
            settings->tcp = true;
            break;
        case 'u':
            settings->udp = true;
            break;
        case 'a':
            settings->arp = true;
            break;
        case '$':
            settings->icmp = true;
            break;
        default:
            if(optopt == 'i') {
                std::cout << "Missing param of interface specifier!" << std::endl;
                bad_interface_opt(ifs);
            }
            else if(optopt == 'n' || optopt == 'p') {
                std::cout << "Parameter is required after!" << argv[optind-1] <<  std::endl;
                exit(EXIT_FAILURE);
            }
            else {
                std::cout << "Unrecognized option: " << argv[optind-1] <<  std::endl;
                exit(EXIT_FAILURE);
            }
        }
    }

    if(!settings->iname) {
        std::cout << "Network interface must be specified!" << std::endl;
        bad_interface_opt(ifs);
    }

    return EXIT_SUCCESS;
}

void print_as_hex(int num, bool wprefix, size_t b_size) {

    if(wprefix)
        std::cout << "0x";

    std::cout << std::setfill('0') << std::setw(b_size*2) << std::hex << num;
}


void print_padding(uint cur_byte) {
    while(cur_byte % LINE_LEN != 0) {
        std::cout << "  ";

        const char *gap = ((cur_byte + 1) % SECTION_LEN == 0) ? "  " : " ";
        std::cout << gap;

        cur_byte++;
    }
}



void print_line_as_chars(const u_char *pkt, uint line_cnt, uint cur_byte) {
    for(uint i = cur_byte - line_cnt; i < cur_byte; i++) {
        if(!isprint(pkt[i])) {
            std::cout << UNPRINTABLE_CHAR;
        }
        else {
            std::cout << pkt[i];
        }

        const char *gap = ((i + 1) % SECTION_LEN == 0) ? " " : "";
        std::cout << gap;
    }
}


void get_frame_info(const u_char *pkt, frame_info_t *info) {
    for(int i = 0; i < 6; i++) {
        info->dst_addr[i] = pkt[i];
    }


    for(int i = 0; i < 6; i++) {
        info->src_addr[i] = pkt[i + 6];
    }

    for(int i = 0; i < 2; i++) {
        info->type[i] = pkt[i + 6 + 6];
    }
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
    const char *filter_str = "";

    //Preparing of pcap_t structure is made due to pcap.h man pages
    if(pcap_lookupnet(settings.iname, &net, &mask, err_buff) < 0) {
        std::cout << "Cannot find given interface '" << settings.iname <<"'!" << std::endl;
        std::cout << "Probably bad network interface name!" << std::endl;
        bad_interface_opt(interfaces);
    }

    pcap_t *pcap_ptr = pcap_open_live(settings.iname, BUFSIZ, 
                                      PCAP_OPENFLAG_PROMISCUOUS, 1000, 
                                      err_buff);

    if(!pcap_ptr) {
        std::cout << "Error while opening: " << err_buff << std::endl;
    }
    
    if(pcap_compile(pcap_ptr, &filter, filter_str, 0, net) < 0) {
        std::cout << "Error while compiling filter! " << pcap_geterr(pcap_ptr);
    }

    if(pcap_setfilter(pcap_ptr, &filter) < 0) {
        std::cout << "Error while setting filter! " << pcap_geterr(pcap_ptr);
    }

    const u_char *pkt;
    pcap_pkthdr pkt_header;

    while(true) {
        pkt = pcap_next(pcap_ptr, &pkt_header);
        //std::cout << pkt_header.len << "\n";

        frame_info_t info;

        get_frame_info(pkt, &info);

        char ts_buffer1[128];
        char ts_buffer2[128];
        std::tm gtime_buffer;

        std::tm *gtime = gmtime(&(pkt_header.ts.tv_sec));
        memcpy(&gtime_buffer, gtime, sizeof(std::tm));
        std::tm *ltime = localtime(&(pkt_header.ts.tv_sec));
        std::strftime(ts_buffer1, 128, "%Y-%m-%dT%H:%M:%S", ltime);
        
        snprintf(ts_buffer2, 128, ".%ld%+d:00", pkt_header.ts.tv_usec, ltime->tm_hour - gtime_buffer.tm_hour);
        std::cout << "ts: " << std::dec << ts_buffer1 << ts_buffer2 << std::endl;
        std::cout << "len: " << std::dec << pkt_header.len;

        std::cout << std::endl;

        std::cout << "dst.: ";
        for(int i = 0; i < 6; i++) {
            print_as_hex(info.dst_addr[i], false, sizeof(char));
        }

        std::cout << std::endl;

        std::cout << "src.: ";
        for(int i = 0; i < 6; i++) {
            print_as_hex(info.src_addr[i], false, sizeof(char));
        }
        std::cout << std::endl;

        std::cout << "type.: ";
        for(int i = 0; i < 2; i++) {
            print_as_hex(info.type[i], false, sizeof(char));
        }

        // print_as_hex((short)info.type, true, sizeof(short));
        std::cout << std::endl;
        
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

    pcap_close(pcap_ptr);



    return EXIT_SUCCESS;
}
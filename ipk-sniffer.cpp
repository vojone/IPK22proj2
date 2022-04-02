#include <iostream>
#include <cstring>
#include <getopt.h>
#include <sys/types.h>
#include <pcap.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define UNSET -1
#define SNAPLEN 65536

typedef struct settings {
    char *iname;
    int port_num;
    bool tcp, udp, arp, icmp;
    int num;
} settings_t;


int get_interfaces(pcap_if_t **interfaces, char *error_buff) {

    if(pcap_findalldevs(interfaces, error_buff) < 0) {
        std::cout << "Error: " << error_buff << "\n";
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

void print_all_interfaces(pcap_if_t *interfaces) {
    pcap_if_t *current;

    for(current = interfaces; current; current = current->next) {
        std::cout << current->name << "\n";
    }
}

void bad_interface_opt(pcap_if_t *interfaces) {
    std::cout << "Active interfaces: " << "\n";

    print_all_interfaces(interfaces);

    exit(EXIT_FAILURE);
}

void check_interface_name(char *if_name, pcap_if_t *interfaces) {
    pcap_if_t *current;

    for(current = interfaces; current; current = current->next) {
        if(strcmp(if_name, current->name) == 0)
            return;
    }

    std::cout << "Invalid interface name!" << "\n";
    bad_interface_opt(interfaces);
}

unsigned int get_port_number(char *port_num_param) {
    char *rest = NULL;
    int port_num = strtoul(port_num_param, &rest, 10);
    if(strlen(rest) > 0) {
        std::cout << "Invalid parameter of -p option (port number)!" << "\n";
        exit(EXIT_FAILURE);
    }

    if(port_num < 0 || port_num > 65536) {
        std::cout << "Parameter of -p option must be valid port number!" << "\n";
        exit(EXIT_FAILURE);
    }

    return (unsigned int)port_num;
}

unsigned int get_number_opt(char *number_param) {
    char *rest = NULL;
    int num = strtoul(number_param, &rest, 10);
    if(strlen(rest) > 0) {
        std::cout << "Invalid parameter of -n option!" << "\n";
        exit(EXIT_FAILURE);
    }

    if(num < 0) {
        std::cout << "Parameter of -n option must be positive integer!" << "\n";
    }

    return num;
}

void init_settings(settings_t *settings) {
    settings->iname = NULL;
    settings->port_num = UNSET;
    settings->num = UNSET;
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
                std::cout << "Missing param of interface specifier." << "\n";
                bad_interface_opt(ifs);
            }
            else if(optopt == 'n' || optopt == 'p') {
                std::cout << "Parameter is required after " << argv[optind-1] << "\n";
                exit(EXIT_FAILURE);
            }
            else {
                std::cout << "Unrecognized option: " << argv[optind-1] << "\n";
                exit(EXIT_FAILURE);
            }
        }
    }

    if(!settings->iname) {
        std::cout << "Network interface must be specified." << "\n";
        bad_interface_opt(ifs);
    }
    else {
        check_interface_name(settings->iname, ifs);
    }

    return EXIT_SUCCESS;
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
    if(pcap_lookupnet(settings.iname, &net, &mask, err_buff) < 0) {
        std::cout << "Error";
    }

    pcap_t *pcap_ptr = pcap_open_live(settings.iname, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, err_buff);
    if(!pcap_ptr) {
        std::cout << "Error while opening";
    }
    
    if(pcap_compile(pcap_ptr, &filter, filter_str, 0, net) < 0) {
        std::cout << "Error";
    }

    if(pcap_setfilter(pcap_ptr, &filter) < 0) {
        std::cout << "Error";
    }

    const u_char *pkt;
    pcap_pkthdr pkt_header;

    while(true) {
        pkt = pcap_next(pcap_ptr, &pkt_header);
        std::cout << pkt_header.len << "\n";
    }

    pcap_close(pcap_ptr);
    (void)pkt;



    return EXIT_SUCCESS;
}
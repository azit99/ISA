#define ARG_ERR 1
#define NO_ERR 0;

typedef struct args{
    char* interface;
    int port;
    int tcp_only;
    int udp_only;
    int packet_cnt;
} argsT;


int parse_args(int argc, char **argv, argsT *out_args);
int print_interfaces();
pcap_t *open_device(const char* interf_name);
int add_filters(pcap_t *dev_handle , argsT args);
void process_packet(u_char *user ,const struct pcap_pkthdr* pkthdr,const u_char* bytes);
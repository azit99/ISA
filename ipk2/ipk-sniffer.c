#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <limits.h>
#include <unistd.h>  
#include <string.h>
#include <netinet/udp.h>  
#include <netinet/tcp.h>  
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <getopt.h>
#include "sniffer.h"
#include <time.h> 


//globalny pcap error buffer 
char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char **argv) {
    argsT args= {NULL, -1, 0, 0, 1};

    if(parse_args(argc, argv, &args)) return ARG_ERR;

    if(!args.interface) {
         print_interfaces(); 
         return 0;
    }

    pcap_t * dev_handle= NULL;
    if(!(dev_handle= pcap_open_live(args.interface, BUFSIZ, 200,-1, errbuf))) {
        fprintf(stderr, "Failed to open device %s for capturing\n", args.interface);
        print_interfaces(); 
        return EXIT_FAILURE;
    }

    if(add_filters(dev_handle, args)) { 
        fprintf(stderr, "Failed to create filter\n");
        return EXIT_FAILURE;
    }

   uint linux_cooked_capture = pcap_datalink(dev_handle) == DLT_LINUX_SLL; //zisti ci sa jedna o linux cooked capture
    
    pcap_loop(dev_handle,args.packet_cnt , process_packet, (u_char*)&linux_cooked_capture);

    return 0;
}

// ciastocne inspirovane https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hex_dump (const u_char* pc, const int len) {
    u_char ascii_buff[17]= "";
    int i;

    for (i = 0; i < len; i++) {        
        if (i%16== 0)  printf ("  %s \n       0x%04x ",ascii_buff,  i);
        printf (" %02x", pc[i]);
        
        ascii_buff[i % 16] = isprint(pc[i]) ? pc[i] :  '.';
        ascii_buff[(i % 16) +1] = 0;
    }

    //zarovnanie posledneho riadku
    for (; i % 16 != 0; i++) printf("   ");

    //ascii reprezentacia
    printf ("  %s\n", ascii_buff);
}
//koniec 

void process_packet(u_char *user ,const struct pcap_pkthdr* header ,const u_char* packet)
{
    //formatovanie a vypis timestampu packetu
    char time_buffer[10];
    strftime(time_buffer, 10, "%H:%M:%S", localtime(&header->ts.tv_sec));
    printf("%s.%ld ", time_buffer, header->ts.tv_usec);

    char source_IP[INET6_ADDRSTRLEN], dest_IP[INET6_ADDRSTRLEN];
    uint16_t source_port, dest_port;
    unsigned ip_header_len; //dlzka hlavicky ip
    uint8_t proto; //protokol transportnej vrstvy
    uint is_linux_cooked= *((uint*)user); //info o tom ci sa jedna o linux cooked capture

    uint ether_h_len= sizeof(struct ether_header);
    if(is_linux_cooked)  ether_h_len += 2; //

    struct ip *ip_header = (struct ip *) (packet + ether_h_len);

    //ipv4 
    if(ip_header->ip_v == 4) { 
        inet_ntop(AF_INET, &(ip_header->ip_src), source_IP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_IP, INET_ADDRSTRLEN);
        ip_header_len = 4*ip_header->ip_hl;
        proto= ip_header->ip_p;

    }
    //ipv6
    else if(ip_header->ip_v == 6)  { 
        struct ip6_hdr *ip6_header = (struct ip6_hdr *) (packet + ether_h_len);
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), source_IP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dest_IP, INET6_ADDRSTRLEN);
        
        ip_header_len = sizeof(struct ip6_hdr);
        proto= ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    }
    //tcp
    if(proto == IPPROTO_TCP){
        struct tcphdr *tcp_header  = (struct tcphdr*) (packet +  ether_h_len + ip_header_len);
        source_port = ntohs(tcp_header->th_sport);
        dest_port = ntohs(tcp_header->th_dport);
    }
    //udp
    else if(proto == IPPROTO_UDP){
        struct udphdr *udp_header  = (struct udphdr*) (packet + ether_h_len + ip_header_len);
        source_port = ntohs(udp_header->uh_sport);
        dest_port = ntohs(udp_header->uh_dport);
    }

    printf("%s : %u > %s : %u \n", source_IP, source_port, dest_IP, dest_port);
    hex_dump(packet, header->len);
}

/*
* Vytvorenie filtra a pridanie nad aktuálne zariadenie
*/
int add_filters(pcap_t *dev_handle, argsT args)
{ 
    if(!dev_handle) return EXIT_FAILURE;

    char filter_string[100]="";

    //filter protokolu
    if(args.udp_only) strcpy(filter_string,"(udp)");
    else if (args.tcp_only) strcpy(filter_string,"(tcp)");
    else  strcpy(filter_string,"(tcp||udp)");

    //filter portu
    if(args.port !=-1) sprintf(filter_string + strlen(filter_string), "and port %d ", args.port);

    bpf_u_int32 addr, mask;
    pcap_lookupnet(args.interface, &addr, &mask, errbuf);
    
    struct bpf_program compiled_filter;

    if(pcap_compile(dev_handle, &compiled_filter,filter_string, 0,addr)) return EXIT_FAILURE;  //zkompilovanie filtra
    if(pcap_setfilter(dev_handle, &compiled_filter)) return EXIT_FAILURE; //aplikacia  filtra nad otvorenym zariadenim

    return EXIT_SUCCESS;
}

/*
* Vypíše dostupné rozhrania
*/
int print_interfaces()
{ 
    pcap_if_t *devices;
    if(pcap_findalldevs(&devices, errbuf)) return EXIT_FAILURE;

   printf("Rozhrania : \n\n");
    while(devices)
    {
        printf("%s \n", devices->name);
        devices= devices->next;
    }
    pcap_freealldevs(devices); //uvolnenie listu
    return EXIT_SUCCESS;
}

/*
* Zpracovanie argumentov
*/
int parse_args(int argc, char **argv, argsT *out_args) 
{    

    static struct option long_options[] = {
        {"tcp", no_argument, NULL, 't'},
        {"udp", no_argument, NULL, 'u'},
        {NULL, 0, NULL, 0}
    };

    char opt;
    
    while((opt = getopt_long(argc, argv, "i:p:n:ut", long_options, NULL)) != -1){ 
        char *err;  
        switch(opt)  
        {  
            case 'i':
                out_args->interface= optarg;
                break;
                
            case 'p':               
                out_args->port=  strtoul(optarg, &err , 10);
                if(! *err == '\0' || out_args->port < 0 || out_args->port > USHRT_MAX){
                    fprintf(stderr, "Port must be positive integer\n");
                    return ARG_ERR;
                }
                break;
               
            case 't':  
                out_args->tcp_only= 1;
                break;
               
            case 'u':  
                out_args->udp_only= 1;
                break;
                
            case 'n': 
                out_args->packet_cnt = strtol(optarg, &err , 10);
                if(*err != '\0'  || out_args->packet_cnt <=  0) {
                    fprintf(stderr, "Packet count must be positive integer/n");
                    return ARG_ERR;
                }
                break;
               
            case ':': 
                return ARG_ERR;

            case '?':  
                return ARG_ERR;  
        }
    }

    //kontrola prebytočných argumentov
    if(optind < argc) {             
        fprintf(stderr,"Excesive arguments!");
        return ARG_ERR;
    }

    return NO_ERR;    
}
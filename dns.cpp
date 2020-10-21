#include <stdlib.h> 
#include <unistd.h>
#include <limits.h>
#include <fstream>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<netinet/in.h>
#include <set>
#include<err.h>
#include<netdb.h>
#include <sys/types.h>       

#define BUFFER_SIZE  65536

#include "dns.h"
using namespace std;

int main(int argc, char **argv) {
    argsT arguments;
    if(process_args(argc, argv, &arguments)) return EXIT_FAILURE;
    set <string> blocked_urls;
    blocked_urls = load_filter_list(arguments.filter_file);
    capture(arguments, blocked_urls);
}

int process_args(int argc, char **argv, argsT *arguments){ 
    char opt;    
    while((opt = getopt(argc, argv, "p:s:f:")) != -1){ 
        char *err;  
        switch(opt){                      
            case 'p':               
                arguments->port = strtoul(optarg, &err , 10);
                if(! *err == '\0' || arguments->port < 0 || arguments->port > USHRT_MAX){
                    fprintf(stderr, "Port must be positive short int\n");
                    return EXIT_FAILURE;
                }
                break;
               
            case 's':  
                arguments->dns_resolver = string(optarg);
                break;
               
            case 'f':  
                arguments->filter_file = string(optarg);
                break;

            case ':': 
            case '?':  
                return EXIT_FAILURE;  
        }
    }
    //kontrola prebytočných argumentov
    if(optind < argc) {             
        fprintf(stderr,"Excesive arguments!");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;    
}

//Nacitanie filtrovanych url
set<string> load_filter_list(string filter_file_path){
    set<string> urls; 
    urls.insert("www.google.com"); //TODO REMOVE
    return urls;
    ifstream file(filter_file_path); //TODO check this  
    for(string line; getline(file, line);){
        if(!line.empty() && line.at(0) != '#'){ //TODO TEST THIS
            urls.insert(line);
            std::cout << line <<endl;
        }
    }
    return urls;
}

int capture(argsT args, set <string> blocked_urls){ 
    char buffer[BUFFER_SIZE];
    struct sockaddr_in server;
    struct sockaddr_in client;    

    server.sin_family = AF_INET;                     
    server.sin_addr.s_addr = htonl(INADDR_ANY);      
    server.sin_port = htons(args.port);                  

    // create the server UDP socket
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) 
        err(1, "socket() failed");

    // binding with the port
    if (bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) 
        err(1, "bind() failed");

    socklen_t length = sizeof(client);
    int msg_size;
    while ((msg_size = recvfrom(fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client, &length)) >= 0){
        //child
        if ((fork()) == 0){ 
            process_request(buffer, msg_size, blocked_urls, args, client, fd);      
        }
    }
    return EXIT_SUCCESS;
}

int process_request (char *buffer, int msg_size, set <string> blocked_urls, argsT arguments, sockaddr_in client, int fd){
    char* orig_buffer = buffer; // ulozenie buffera pre poizitie pri preposlani
    dns_headerT *orig_header  = (dns_headerT *) buffer;    
    buffer+= sizeof(dns_header);
    char domain_name[256] = {0};
    parse_domain_name(buffer, domain_name);
    buffer += strlen(domain_name)+2; // +1 pre prvy oktet obsahujuci pocet a +1 pre \0 na konci
    uint16_t * qtype= (uint16_t *) buffer;
    buffer+=sizeof(uint16_t);
    cout << domain_name; //TODO REMOVE 
    
    if(ntohs(*qtype) != 1){ //test ci sa jedna o A zaznam query 
        printf(" not suported operation %d ", ntohs(*qtype) );  // TODO REMOVE
        dns_headerT resp= get_err_response(4, orig_header->id);
        int i = sendto(fd,&resp, sizeof(dns_header) ,0 ,(struct sockaddr *) &client, sizeof(client)); 
        if (i == -1) err(1,"sendto() failed 132");
        else if (i != sizeof(resp)) err(1,"sendto(): buffer written partially 124");    
        close(fd);
        return EXIT_SUCCESS;        
    }
    
    if(blocked_urls.count(string(domain_name))){ // jedna sa o blokovanu domenu?
        cerr << "this url is blocked" << sizeof(dns_header) ; 
        dns_headerT resp= get_err_response(5, orig_header->id);
        int i = sendto(fd,&resp, sizeof(dns_header) ,0 ,(struct sockaddr *) &client, sizeof(client)); 
        if (i == -1) err(1,"sendto() failed 132");
        else if (i != sizeof(resp)) err(1,"sendto(): buffer written partially 134");    
        close(fd);
        return EXIT_SUCCESS; 
    }

    //reply to client
    int resp_len;
    char * response = ask_server(orig_buffer, msg_size, arguments.dns_resolver.c_str(), &resp_len);
    dns_headerT* hdr = (dns_headerT*) response;
    hdr->id= orig_header->id;
    int i = sendto(fd,response, resp_len ,0 ,(struct sockaddr *) &client, sizeof(client)); 
    if (i == -1) err(1,"sendto() failed 132");
    else if (i != resp_len) err(1,"sendto(): buffer written partially 133");    
    close(fd);
    return EXIT_SUCCESS;
}

char* ask_server(char* message, int msg_size, const char* server_ip, int* response_len){    
    int sock;
    struct sockaddr_in server, from;
    static char buffer[BUFFER_SIZE]={0};

    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)  err(1,"socket() failed\n");

    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(server_ip);
    server.sin_port = htons(53);
   
    //poslanie dotazu na dns server
    int i = sendto(sock,message, msg_size ,0 ,(struct sockaddr *) &server, sizeof(server)); 
    if (i == -1) err(1,"sendto() failed 152");
    else if (i != msg_size) err(1,"sendto(): buffer written partially");

    //precitanie odpovede
    socklen_t lenght; 
    if ((i = recvfrom(sock,buffer, BUFFER_SIZE,0,(struct sockaddr *) &from, &lenght)) == -1)   
    err(1,"recvfrom() failed");
    if (msg_size == -1)
        err(1,"reading from socket failed");

    close(sock);
    *response_len = i;
    return buffer;        
}

void parse_domain_name(char* buffer, char* domain_name)
{ 
    unsigned char cnt= *buffer;
    buffer ++; 
    while (*buffer){
        if(cnt  == 0){ 
            cnt = *buffer; 
            domain_name[strlen(domain_name)] = '.';
            }
        else {
            cnt --;
            domain_name[strlen(domain_name)] = *buffer;
        }
        buffer ++;    
    }
}

dns_headerT get_err_response(int err_code, uint16_t id){
    dns_headerT hdr;
    hdr.id = id;
    hdr.qr = 1;
    hdr.opcode = 0;
    hdr.aa = 0;
    hdr.tc = 0;
    hdr.rd = 1;
    hdr.ra = 1;
    hdr.z = 0;
    hdr.rcode= err_code;
    hdr.num_of_q = 0;
    hdr.num_of_answ_rr = 0;
    hdr.num_of_auth_rr = 0 ;

    return hdr;
}
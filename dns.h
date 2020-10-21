#include <string.h>
#include <set>
#include <stdint.h>

using namespace std; 

typedef struct args{
    int port;
    std::string dns_resolver; 
    std::string filter_file;
} argsT;

typedef struct dns_header{
    uint16_t id;
    unsigned int qr :1;
    unsigned int opcode :4;
    unsigned int aa :1;
    unsigned int tc :1;
    unsigned int rd :1;
    unsigned int ra :1;
    unsigned int z :1;
    unsigned int rcode :4;
    uint16_t num_of_q;
    uint16_t num_of_answ_rr;
    uint16_t num_of_auth_rr;
    uint16_t num_of_addit_rr;
} dns_headerT;


int process_args(int argc, char **argv, argsT *arguments);
std::set<std::string> load_filter_list(string filter_file_path); 
int process_request(char *buffer, int msg_size, std::set <std::string> blocked_urls, argsT arguments, sockaddr_in client, int fd);
int capture(argsT args, std::set <std::string> blocked_urls);
void parse_domain_name(char* buffer, char* domain_name);
char* ask_server(char* buffer, int msg_size, const char *server_ip, int *response_len);
dns_headerT get_err_response(int err_code, uint16_t id);
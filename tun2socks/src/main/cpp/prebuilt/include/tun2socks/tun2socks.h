#define PROGRAM_NAME "tun2socks"
#define CLIENT_SOCKS_RECV_BUF_SIZE 8192
#define DEFAULT_UDPGW_MAX_CONNECTIONS 256
#define DEFAULT_UDPGW_CONNECTION_BUFFER_SIZE 8
#define UDPGW_RECONNECT_TIME 5000
#define UDPGW_KEEPALIVE_TIME 10000
#define SOCKS_UDP_SEND_BUFFER_PACKETS 16

#ifdef __cplusplus
extern "C" {
#endif
int tun2socks_start(int argc, char **argv);
void tun2socks_terminate(void);
void tun2socks_print_help(const char *name);
void tun2socks_print_version(void);
#ifdef __cplusplus
}
#endif

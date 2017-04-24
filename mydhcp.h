// include header file
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

// macro
sigset_t sigset;
#define SIGINIT do{sigemptyset(&sigset); sigaddset(&sigset, SIGALRM);}while(0)
#define SIGBLK do{sigprocmask(SIG_BLOCK, &sigset, NULL);}while(0)
#define SIGUNBLK do{sigprocmask(SIG_UNBLOCK, &sigset, NULL);}while(0)

// buffer size
#define BUF_LEN 512

// DHCP message type
#define DHCPINIT 0
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPREPLY 4
#define DHCPRELEASE 5

// DHCP message code
#define CODE_OK 0
#define CODE_OFFER_ERR 129
#define CODE_REPLY_ERR 130
#define CODE_REQ_ASSIGN 10
#define CODE_REQ_EXTENSION 11

// DHCP client status
#define CSTAT_INIT 0
#define CSTAT_WAIT_OFFER 1
#define CSTAT_WAIT_ACK 2
#define CSTAT_GET_IP 3
#define CSTAT_END 4

// DHCP server status
#define SSTAT_INIT 0
#define SSTAT_WAIT_DSC 1
#define SSTAT_WAIT_REQ 2
#define SSTAT_ALLOC_IP 3
#define SSTAT_END 4

// DHCP port number
#define DHCP_PORT "51230"

// time to live
#define TTL 40

// time out
#define TIMEOUT 10

// packet format
struct dhcph {
	uint8_t type;	// message type
	uint8_t code;	// message code
	uint16_t ttl;	// time to live
	in_addr_t address;	// IP address
	uint32_t netmask;	// netmask
};

// client management
struct client_entry {
	struct client_entry *fp;	// client list forward pointer
	struct client_entry *bp;	// client list backward pointer
	struct client_entry *tout_fp;	// timeout list forward pointer
	struct client_entry *tout_bp;	// timeout list backward pointer
	int stat;	// client state
	int start_time;	// star time
	int exp_time;	// expiration time
	struct in_addr cli_addr;	// client IP address
	uint32_t netmask;	// client netmask
	uint16_t cli_port;	// client port number
	struct in_addr alloc_addr;	// allocated IP address
};

// client management list head
struct client_entry client_head;

// time-out management list head
struct client_entry timeout_head;

// IP address and netmask management
struct ip_entry {
	struct ip_entry *fp;	// forward pointer
	struct ip_entry *bp;	// backward pointer
	char address[BUF_LEN];	// IP address
	char netmask[BUF_LEN];	// netmask
	int busy_flag;	// 1: busy, 0: free
};

// IP address and netmask management list head
struct ip_entry ip_head;

// function
extern void set_dhcph(struct dhcph *, uint8_t, uint8_t, uint16_t, in_addr_t, uint32_t);
extern void show_dhcph(struct dhcph *);

extern void insert_ip(struct ip_entry*, struct ip_entry *);
extern void remove_ip(struct ip_entry*);
extern struct ip_entry *search_ip(struct dhcph *);
extern struct ip_entry *search_ip_timeout(struct in_addr);
extern void alloc_ip();
extern char *convert_addr(uint32_t);
extern void show_alloc_ip(struct dhcph *);
extern void show_get_ip(struct dhcph *);
extern void insert_client(struct client_entry *, struct client_entry *);
extern void remove_client(struct client_entry *);
extern struct client_entry *search_client(struct in_addr a);
extern void insert_timeout(struct client_entry *, struct client_entry *);
extern int insert_timeout_seq(struct client_entry *);
extern void remove_timeout(struct client_entry *);
extern struct client_entry *search_timeout(struct in_addr);
extern void set_dhcph(struct dhcph *, uint8_t, uint8_t, uint16_t, in_addr_t, uint32_t);
extern void print_msg_type(int);
extern void show_dhcph_send(struct dhcph *);
extern void show_dhcph_recv(struct dhcph *);
extern void show_cstat_trans(int, int);
extern void print_cstat(int);
extern void print_sstat(int);
extern void show_sstat_trans(int, int);

extern void f_stat0_msg0(struct client_entry *, struct dhcph *);
extern void f_stat0_msg1(struct client_entry *, struct dhcph *);
extern void f_stat0_msg2(struct client_entry *, struct dhcph *);
extern void f_stat0_msg3(struct client_entry *, struct dhcph *);
extern void f_stat0_msg4(struct client_entry *, struct dhcph *);
extern void f_stat0_msg5(struct client_entry *, struct dhcph *);

extern void f_stat1_msg0(struct client_entry *, struct dhcph *);
extern void f_stat1_msg1(struct client_entry *, struct dhcph *);
extern void f_stat1_msg2(struct client_entry *, struct dhcph *);
extern void f_stat1_msg3(struct client_entry *, struct dhcph *);
extern void f_stat1_msg4(struct client_entry *, struct dhcph *);
extern void f_stat1_msg5(struct client_entry *, struct dhcph *);

extern void f_stat2_msg0(struct client_entry *, struct dhcph *);
extern void f_stat2_msg1(struct client_entry *, struct dhcph *);
extern void f_stat2_msg2(struct client_entry *, struct dhcph *);
extern void f_stat2_msg3(struct client_entry *, struct dhcph *);
extern void f_stat2_msg4(struct client_entry *, struct dhcph *);
extern void f_stat2_msg5(struct client_entry *, struct dhcph *);

extern void f_stat3_msg0(struct client_entry *, struct dhcph *);
extern void f_stat3_msg1(struct client_entry *, struct dhcph *);
extern void f_stat3_msg2(struct client_entry *, struct dhcph *);
extern void f_stat3_msg3(struct client_entry *, struct dhcph *);
extern void f_stat3_msg4(struct client_entry *, struct dhcph *);
extern void f_stat3_msg5(struct client_entry *, struct dhcph *);

extern void f_stat4_msg0(struct client_entry *, struct dhcph *);
extern void f_stat4_msg1(struct client_entry *, struct dhcph *);
extern void f_stat4_msg2(struct client_entry *, struct dhcph *);
extern void f_stat4_msg3(struct client_entry *, struct dhcph *);
extern void f_stat4_msg4(struct client_entry *, struct dhcph *);
extern void f_stat4_msg5(struct client_entry *, struct dhcph *);

extern void (*functab[][6])(struct client_entry *, struct dhcph *);

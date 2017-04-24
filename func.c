#include "mydhcp.h"

// insert *p at the tail to IP address and netmask management list
// *h --- list head pointer
// *p --- insert pointer
void
insert_ip(struct ip_entry *h, struct ip_entry *p)
{
	SIGINIT;
	SIGBLK;
	p->bp = h;
	p->fp = h->fp;
	h->fp->bp = p;
	h->fp = p;
	SIGUNBLK;
}

// remove *p from IP address and netmask management list
void
remove_ip(struct ip_entry *p)
{
	SIGINIT;
	SIGBLK;
	p->bp->fp = p->fp;
	p->fp->bp = p->bp;
	SIGUNBLK;
}

// search msg->address from IP address and netmask management list
struct ip_entry *
search_ip(struct dhcph *msg)
{
	struct ip_entry *p;

	SIGINIT;
	SIGBLK;
	for (p = ip_head.fp; p != &ip_head; p = p->fp) {
		if (inet_addr(p->address) == msg->address) {
			return p;
		}
	}
	SIGUNBLK;
	return NULL;
}


struct ip_entry *
search_ip_timeout(struct in_addr a)
{
	struct ip_entry *p;

	SIGINIT;
	SIGBLK;
	for (p = ip_head.fp; p != &ip_head; p = p->fp) {
		if (inet_addr(p->address) == a.s_addr) {
			return p;
		}
	}
	SIGUNBLK;
	return NULL;
}

void alloc_ip()
{
	struct ip_entry *p;

	p = ip_head.fp;
	remove_ip(p);
	insert_ip(ip_head.bp, p);
}

char *
convert_addr(uint32_t a)
{
	struct in_addr b;
	char tmp[5];

	if (a != 0) {
		memcpy(tmp, &a, sizeof(uint32_t));
		b.s_addr = *((unsigned long *)tmp);
		tmp[4] = '\0';
		return inet_ntoa(b);
	}

	return "0";

}

void
show_alloc_ip(struct dhcph *msg)
{
	printf("=================================================\n");
	printf("IP address and netmask is allocated\n");
	printf("IP address  : %s\n", convert_addr(msg->address));
	printf("netmask     : %s\n", convert_addr(msg->netmask));
	printf("Time to Live: %d\n", msg->ttl);
	printf("=================================================\n");
}

void
show_get_ip(struct dhcph *msg)
{
	printf("=================================================\n");
	printf("IP address and netmask is assigned to this client\n");
	printf("IP address  : %s\n", convert_addr(msg->address));
	printf("netmask     : %s\n", convert_addr(msg->netmask));
	printf("Time to Live: %d\n", msg->ttl);
	printf("=================================================\n");
}

// insert *p at the tail to client management list
// *h --- list head pointer
// *p --- insert pointer
void
insert_client(struct client_entry *h, struct client_entry *p)
{
	SIGINIT;
	SIGBLK;
	p->bp = h;
	p->fp = h->fp;
	h->fp->bp = p;
	h->fp = p;
	SIGUNBLK;
}

// remove *p from client management list
void
remove_client(struct client_entry *p)
{
	SIGINIT;
	SIGBLK;
	p->fp->bp = p->bp;
	p->bp->fp = p->fp;
	SIGUNBLK;
}

// search msg->address from IP address and netmask management list
struct client_entry *
search_client(struct in_addr a)
{
	struct client_entry *p;

	SIGINIT;
	SIGBLK;
	for (p = client_head.fp; p != &client_head; p = p->fp) {
		if (p->cli_addr.s_addr == a.s_addr) {
			SIGUNBLK;
			return p;
		}
	}
	SIGUNBLK;
	return NULL;
}

// insert *p at the tail to client time-out management list
// *h --- list head pointer
// *p --- insert pointer
void
insert_timeout(struct client_entry *h, struct client_entry *p)
{
	SIGINIT;
	SIGBLK;
	p->tout_bp = h;
	p->tout_fp = h->tout_fp;
	h->tout_fp->tout_bp = p;
	h->tout_fp = p;
	SIGUNBLK;
}

int
insert_timeout_seq(struct client_entry *cli)
{
	struct client_entry *p;

	SIGINIT;
	SIGBLK;
	/*
	printf("%d, %d, %d\n", timeout_head.tout_fp->exp_time,
			timeout_head.tout_fp->tout_fp->exp_time, timeout_head.exp_time);
	*/
	for (p = timeout_head.tout_fp; p != &timeout_head; p = p->tout_fp) {
		// printf("p->exp_time: %d, cli->exp_time: %d\n", p->exp_time, cli->exp_time);
		if (p->exp_time > cli->exp_time) {
			insert_timeout(p->tout_bp, cli);
			SIGUNBLK;
			return 0;
		}
	}
	insert_timeout(timeout_head.tout_bp, cli);
	SIGUNBLK;
	return -1;
}

// remove *p from client time-out management list
void
remove_timeout(struct client_entry *p)
{
	SIGINIT;
	SIGBLK;
	p->tout_bp->tout_fp = p->tout_fp;
	p->tout_fp->tout_bp = p->tout_bp;
	SIGUNBLK;
}

struct client_entry *
search_timeout(struct in_addr a)
{
	struct client_entry *p;

	SIGINIT;
	SIGBLK;
	for (p = timeout_head.tout_fp; p != &timeout_head; p = p->tout_fp) {
		if (p->cli_addr.s_addr == a.s_addr) {
			SIGUNBLK;
			return p;
		}
	}
	SIGUNBLK;
	return NULL;
}

// set DHCP message
void
set_dhcph(struct dhcph *msg, uint8_t type, uint8_t code,
		uint16_t ttl, in_addr_t address, uint32_t netmask)
{
	msg->type = type;
	msg->code = code;
	msg->ttl = ttl;
	msg->address = address;
	msg->netmask = netmask;
}

// print DHCP message type
void
print_msg_type(int type)
{
	switch (type) {
	case DHCPDISCOVER:
		printf("DISCOVER");
		break;
	case DHCPOFFER:
		printf("OFFER");
		break;
	case DHCPREQUEST:
		printf("REQUEST");
		break;
	case DHCPREPLY:
		printf("REPRLY");
		break;
	case DHCPRELEASE:
		printf("DHCPRELEASE");
		break;
	default:
		printf("undefined");
		break;
	}
	printf("(%d)", type);
}

// print dhcp sending message
void
show_dhcph_send(struct dhcph *msg)
{
	printf("********** send");
	printf(" **********\n");
	printf("Type        : ");
	print_msg_type(msg->type);
	printf("\n");
	printf("Code        : %u\n", msg->code);
	printf("Time to Live: %u\n", msg->ttl);
	printf("IP address  : %s\n", convert_addr(msg->address));
	printf("Netmask     : %s\n", convert_addr(msg->netmask));
	printf("**************************\n");
}

// print dhcp receive message
void
show_dhcph_recv(struct dhcph *msg)
{
	printf("********* receive");
	printf(" ********\n");
	printf("Type        : ");
	print_msg_type(msg->type);
	printf("\n");
	printf("Code        : %u\n", msg->code);
	printf("Time to Live: %u\n", msg->ttl);
	printf("IP address  : %s\n", convert_addr(msg->address));
	printf("Netmask     : %s\n", convert_addr(msg->netmask));
	printf("**************************\n");
}

// print client state
void
print_cstat(int stat)
{
	switch (stat) {
	case CSTAT_INIT:
		printf("CSTAT_INIT");
		break;
	case CSTAT_WAIT_OFFER:
		printf("CSTAT_WAIT_OFFER");
		break;
	case CSTAT_WAIT_ACK:
		printf("CSTAT_WAIT_ACK");
		break;
	case CSTAT_GET_IP:
		printf("CSTAT_GET_IP");
		break;
	case CSTAT_END:
		printf("CSTAT_END");
		break;
	default:
		printf("undefined client state");
		break;
	}
	printf("(%d)", stat);
}

// print client state transition
void
show_cstat_trans(int prev_stat, int next_stat)
{
	printf("\nclient state transition: ");
	print_cstat(prev_stat);
	printf(" -> ");
	print_cstat(next_stat);
	printf("\n\n");
}

// print server state
void
print_sstat(int stat)
{
	switch (stat) {
	case SSTAT_INIT:
		printf("SSTAT_INIT");
		break;
	case SSTAT_WAIT_DSC:
		printf("SSTAT_WAIT_DSC");
		break;
	case SSTAT_WAIT_REQ:
		printf("SSTAT_WAIT_REQ");
		break;
	case SSTAT_ALLOC_IP:
		printf("SSTAT_ALLOC_IP");
		break;
	case SSTAT_END:
		printf("SSTAT_END");
		break;
	default:
		printf("undefined server state");
		break;
	}
	printf("(%d)", stat);
}

// print server  state transition
void
show_sstat_trans(int prev_stat, int next_stat)
{
	printf("\nserver state transition: ");
	print_sstat(prev_stat);
	printf(" -> ");
	print_sstat(next_stat);
	printf("\n\n");
}

/*
void
f_stat0_msg0(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat0_msg1(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat0_msg2(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat0_msg3(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat0_msg4(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat0_msg5(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat1_msg0(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat1_msg1(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat1_msg2(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat1_msg3(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat1_msg4(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat1_msg5(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat2_msg0(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat2_msg1(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat2_msg2(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat2_msg3(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat2_msg4(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat2_msg5(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat3_msg0(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat3_msg1(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat3_msg2(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat3_msg3(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat3_msg4(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat3_msg5(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat4_msg0(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat4_msg1(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat4_msg2(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat4_msg3(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat4_msg4(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat4_msg5(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat5_msg0(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat5_msg1(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat5_msg2(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat5_msg3(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat5_msg4(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
f_stat5_msg5(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "undefined\n");
	exit(1);
}

void
(*functab[][6])(struct client_entry *cli, struct dhcph *msg) = {
	{f_stat0_msg0, f_stat0_msg1, f_stat0_msg2, f_stat0_msg3, f_stat0_msg4, f_stat0_msg5},
	{f_stat1_msg0, f_stat1_msg1, f_stat1_msg2, f_stat1_msg3, f_stat1_msg4, f_stat1_msg5},
	{f_stat2_msg0, f_stat2_msg1, f_stat2_msg2, f_stat2_msg3, f_stat2_msg4, f_stat2_msg5},
	{f_stat3_msg0, f_stat3_msg1, f_stat3_msg2, f_stat3_msg3, f_stat3_msg4, f_stat3_msg5},
	{f_stat4_msg0, f_stat4_msg1, f_stat4_msg2, f_stat4_msg3, f_stat4_msg4, f_stat4_msg5},
	{f_stat5_msg0, f_stat5_msg1, f_stat5_msg2, f_stat5_msg3, f_stat5_msg4, f_stat5_msg5},
};
*/

#include "mydhcp.h"

int sock;	// socket descripter
struct sockaddr_in skt;	// socket address of the client
socklen_t sktlen = sizeof(skt);
struct timeval timeout;	// TIMEOUT
struct itimerval timer;	// TTL
int timer_start_flag = 0;
struct client_entry *curt_timer = NULL;	// current timer

void
start_timer(long timeout)
{
	timer.it_value.tv_sec = timeout;
	timer.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &timer, NULL);
}

void
stop_timer()
{
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &timer, NULL);
}

void
alrm_func(int signo)
{
	struct client_entry *next_timer = NULL;
	struct ip_entry *p;
	int prev_stat;

	stop_timer();
	if (curt_timer->stat == SSTAT_WAIT_REQ) {
		printf("time-out 10 seconds\n");
	} else {
		printf("time-out 40 seconds\n");
	}
	if (curt_timer->tout_fp != &timeout_head) {
		next_timer = curt_timer->tout_fp;
		start_timer(next_timer->exp_time - curt_timer->exp_time);
		//printf("start_timer(%d)\n", next_timer->exp_time - curt_timer->exp_time);
	}
	remove_timeout(curt_timer);
	prev_stat = curt_timer->stat;
	curt_timer->stat = SSTAT_END;
	show_sstat_trans(prev_stat, curt_timer->stat);
	printf("<<");
	print_sstat(curt_timer->stat);
	printf(">>\n");
	//printf("release IP address of this client: %s\n", convert_addr(curt_timer->cli_addr.s_addr));
	if ((p = search_ip_timeout(curt_timer->alloc_addr)) == NULL) {
		fprintf(stderr, "not found this IP address in time-out management list\n");
		exit(1);
	}
	p->busy_flag = 0;
	remove_client(curt_timer);
	free(curt_timer);
	curt_timer = next_timer;
	if (timeout_head.tout_fp == &timeout_head) {
		timer_start_flag = 0;
	}
}

void
f_stat0_err(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "server undefined behavior\n");
	fprintf(stderr, "msg0, %d\n", msg->type);
	//exit(1);
}

void
f_stat0_msg5(struct client_entry *cli, struct dhcph *msg)
{
	struct client_entry *next_timer = NULL;
	struct client_entry *p;
	struct timeval t;

	if (curt_timer != NULL) {
		if (curt_timer->cli_addr.s_addr == cli->cli_addr.s_addr) {
			stop_timer();
			// printf("received extension REQUEST from the client before time-out\n");
		}
		if (curt_timer->tout_fp != &timeout_head) {
			gettimeofday(&t, NULL);	// get current time
			next_timer = curt_timer->tout_fp;
			start_timer(next_timer->exp_time - t.tv_sec);
			// printf("start_timer(%d)\n", next_timer->exp_time - t.tv_sec);
		}
		remove_timeout(curt_timer);
		curt_timer = next_timer;
		if (timeout_head.tout_fp == &timeout_head) {
			timer_start_flag = 0;
		}
	} else if ((p = search_timeout(cli->cli_addr)) != NULL) {
		remove_timeout(p);
	}
	cli->stat = SSTAT_END;
}

void
f_stat1_err(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "server undefined behavior\n");
	fprintf(stderr, "msg0, %d\n", msg->type);
	//exit(1);
}

void
f_stat1_msg1(struct client_entry *cli, struct dhcph *msg)
{
	struct timeval t;

	if (ip_head.fp->busy_flag) {
		fprintf(stderr, "all IP address is busy\n");
		set_dhcph(msg, DHCPOFFER, CODE_OFFER_ERR/* 129 */, TTL, 0, 0);
	} else {
		set_dhcph(msg, DHCPOFFER, CODE_OK/* 0 */, TTL,
				inet_addr(ip_head.fp->address), inet_addr(ip_head.fp->netmask));
		cli->alloc_addr.s_addr = inet_addr(ip_head.fp->address);
		cli->netmask = inet_addr(ip_head.fp->netmask);
		cli->stat = SSTAT_WAIT_REQ;
	}
	if (sendto(sock, (char *)msg, sizeof(*msg), 0,
				(struct sockaddr *)&skt, sktlen) < 0) {
		perror("sendto");
		exit(1);
	}
	/*
	struct client_entry *p;
	for (p = client_head.fp; p != &client_head; p = p->fp) {
		printf("client stat: %d\n", p->stat);
	}
	*/
	show_dhcph_send(msg);
	if (cli->stat == SSTAT_WAIT_REQ) {
		gettimeofday(&t, NULL);	// get current time
		cli->start_time = timeout.tv_sec;
		cli->exp_time = timeout.tv_sec + TIMEOUT;
		insert_timeout_seq(cli);
		if (timer_start_flag++ == 0) {
			curt_timer = cli;
			start_timer(TIMEOUT);
			//printf("start_timer(%d)\n", TIMEOUT);
		} else if (curt_timer->exp_time > cli->exp_time) {
			stop_timer();
			curt_timer = cli;
			start_timer(TIMEOUT);
			//printf("start_timer(%d)\n", TIMEOUT);
		}
		/*
		struct client_entry *p;
		for (p = timeout_head.tout_fp; p != &timeout_head; p = p->tout_fp) {
			printf("IP address: %s, exp_time: %d\n",
					inet_ntoa(p->cli_addr), p->exp_time);
		}
		*/
	}
	/*
	struct client_entry *tmp;
	for (tmp = timeout_head.tout_fp; tmp != &timeout_head; tmp = tmp->tout_fp) {
		printf("timer IP: %s, exp_time: %d\n", inet_ntoa(tmp->cli_addr), tmp->exp_time);
	}
	*/
}

void
f_stat1_msg5(struct client_entry *cli, struct dhcph *msg)
{
	cli->stat = SSTAT_END;
}

void
f_stat2_err(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "server undefined behavior\n");
	fprintf(stderr, "msg0, %d\n", msg->type);
	//exit(1);
}

void
f_stat2_msg3(struct client_entry *cli, struct dhcph *msg)
{
	struct client_entry *p;
	struct client_entry *next_timer = NULL;
	struct ip_entry *q;
	struct timeval t;

	if (curt_timer != NULL) {
		if (cli->cli_addr.s_addr == curt_timer->cli_addr.s_addr) {
			stop_timer();
			if (curt_timer->tout_fp != &timeout_head) {
				gettimeofday(&t, NULL);	// get current time
				next_timer = curt_timer->tout_fp;
				start_timer(next_timer->exp_time - t.tv_sec);
				//printf("start_timer(%d)\n", next_timer->exp_time - t.tv_sec);
			}
			remove_timeout(curt_timer);
			curt_timer = next_timer;
			if (timeout_head.tout_fp == &timeout_head) {
				timer_start_flag = 0;
			}
		} else if ((p = search_timeout(cli->cli_addr)) != NULL) {
			remove_timeout(p);
		}
	}
	if ((q = search_ip(msg)) == NULL) {
		fprintf(stderr, "this IP address is already free\n");
		exit(1);
	}
	if (q->busy_flag) {
		fprintf(stderr, "this IP address is already busy\n");
		set_dhcph(msg, DHCPREPLY, CODE_REPLY_ERR/* 130 */, TTL,
				msg->address, msg->netmask);
	} else {
		set_dhcph(msg, DHCPREPLY, CODE_OK/* 0 */, TTL,
				msg->address, msg->netmask);
		q->busy_flag = 1;
		alloc_ip();
		show_alloc_ip(msg);
		/*
		struct ip_entry *tmp;
		for (tmp = ip_head.fp; tmp != &ip_head; tmp = tmp->fp) {
			printf("client management IP: %s, netmask: %d, busy_flag: %d\n",
					tmp->address, tmp->netmask, tmp->busy_flag);
		}
		*/
		gettimeofday(&t, NULL);	// get current time
		cli->start_time = timeout.tv_sec;
		cli->exp_time = timeout.tv_sec + TTL;
		insert_timeout_seq(cli);
		if (timer_start_flag++ == 0) {
			curt_timer = cli;
			start_timer(TTL);
			//printf("start_timer(%d)\n", TTL);
		} else if (curt_timer->exp_time > cli->exp_time) {
			insert_timeout_seq(cli);
			stop_timer();
			curt_timer = cli;
			start_timer(TTL);
			//printf("start_timer(%d)\n", TTL);
		}

		/*
		struct client_entry *tmp2;
		for (tmp2 = timeout_head.tout_fp; tmp2 != &timeout_head; tmp2 = tmp2->tout_fp) {
			printf("timeout management IP: %s, exp_time: %d, start_time: %d\n",
					inet_ntoa(tmp2->cli_addr), tmp2->exp_time, tmp2->start_time);
		}
		*/
		cli->stat = SSTAT_ALLOC_IP;
	}
	if (sendto(sock, (char *)msg, sizeof(*msg), 0,
				(struct sockaddr *)&skt, sktlen) < 0) {
		perror("sendto");
		exit(1);
	}
	show_dhcph_send(msg);
}

void
f_stat2_msg5(struct client_entry *cli, struct dhcph *msg)
{
	cli->stat = SSTAT_END;
}

void
f_stat3_err(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "server undefined behavior\n");
	fprintf(stderr, "msg0, %d\n", msg->type);
	//exit(1);
}

void
f_stat3_msg3(struct client_entry *cli, struct dhcph *msg)
{
	struct client_entry *next_timer = NULL;
	struct client_entry *p;
	struct timeval t;

	/*
	struct client_entry *tmp;
	for (tmp = timeout_head.tout_fp; tmp != &timeout_head; tmp = tmp->tout_fp) {
		printf("timeout management IP: %s, exp_time: %d, start_time: %d\n",
				inet_ntoa(tmp->cli_addr), tmp->exp_time, tmp->start_time);
	}
	*/

	if (msg->code == CODE_REQ_EXTENSION/* 11 */) {
		if (curt_timer != NULL) {
			if (curt_timer->cli_addr.s_addr == cli->cli_addr.s_addr) {
				stop_timer();
				//printf("received extension REQUEST from the client before time-out\n");
			}
			if (curt_timer->tout_fp != &timeout_head) {
				gettimeofday(&t, NULL);	// get current time
				next_timer = curt_timer->tout_fp;
				start_timer(next_timer->exp_time - t.tv_sec);
				//printf("start_timer(%d)\n", next_timer->exp_time - t.tv_sec);
			}
			remove_timeout(curt_timer);
			curt_timer = next_timer;
			if (timeout_head.tout_fp == &timeout_head) {
				timer_start_flag = 0;
			}
		} else if ((p = search_timeout(cli->cli_addr)) != NULL) {
			remove_timeout(p);
		}
		set_dhcph(msg, DHCPREPLY, CODE_OK/* 0 */, TTL, msg->address, msg->netmask);
		if (sendto(sock, (char *)msg, sizeof(*msg), 0,
				(struct sockaddr *)&skt, sktlen) < 0) {
			perror("sendto");
			exit(1);
		}
		show_dhcph_send(msg);
		gettimeofday(&t, NULL);	// get current time
		cli->start_time = t.tv_sec;
		cli->exp_time = t.tv_sec + TTL;
		insert_timeout_seq(cli);
		if (timer_start_flag++ == 0) {
			curt_timer = cli;
			start_timer(TTL);
			//printf("start_timer(%d)", TTL);
		} else if (curt_timer->exp_time > cli->exp_time) {
			insert_timeout_seq(cli);
			stop_timer();
			curt_timer = cli;
			start_timer(TTL);
			//printf("start_timer(%d)", TTL);
		}
		/*
		for (tmp = timeout_head.tout_fp; tmp != &timeout_head; tmp = tmp->tout_fp) {
			printf("timeout management IP: %s, exp_time: %d, start_time: %d\n",
					inet_ntoa(tmp->cli_addr), tmp->exp_time, tmp->start_time);
		}
		*/
	} else {
		fprintf(stderr, "received undefined code in REQUEST: %d\n", msg->code);
	}
}

void
f_stat3_msg5(struct client_entry *cli, struct dhcph *msg)
{
	struct client_entry *next_timer = NULL;
	struct client_entry *p;
	struct timeval t;

	if (curt_timer != NULL) {
		if (curt_timer->cli_addr.s_addr == cli->cli_addr.s_addr) {
			stop_timer();
			// printf("received extension REQUEST from the client before time-out\n");
		}
		if (curt_timer->tout_fp != &timeout_head) {
			gettimeofday(&t, NULL);	// get current time
			next_timer = curt_timer->tout_fp;
			start_timer(next_timer->exp_time - t.tv_sec);
			// printf("start_timer(%d)\n", next_timer->exp_time - t.tv_sec);
		}
		remove_timeout(curt_timer);
		curt_timer = next_timer;
		if (timeout_head.tout_fp == &timeout_head) {
			timer_start_flag = 0;
		}
	} else if ((p = search_timeout(cli->cli_addr)) != NULL) {
		remove_timeout(p);
	}
	cli->stat = SSTAT_END;
}

void
f_stat4_err(struct client_entry *cli, struct dhcph *msg)
{
	fprintf(stderr, "server undefined behavior\n");
	fprintf(stderr, "msg0, %d\n", msg->type);
	//exit(1);
}

void
f_stat4_nan(struct client_entry *cli, struct dhcph *msg)
{
	struct ip_entry *p;

	printf("<<");
	print_sstat(cli->stat);
	printf(">>\n");
	//printf("release IP address of this client: %s\n", convert_addr(cli->alloc_addr));
	if ((p = search_ip(msg)) == NULL) {
		//fprintf(stderr, "this IP address is already free\n");
		//exit(1);
		;
	} else {
		p->busy_flag = 0;
	}

	//printf("remove this client from client management list\n");
	//// I have to write this
	remove_client(cli);
	free(cli);
}

void
(*functab[][6])(struct client_entry *cli, struct dhcph *msg) = {
	{f_stat0_err, f_stat0_err, f_stat0_err, f_stat0_err, f_stat0_err, f_stat0_msg5},
	{f_stat1_err, f_stat1_msg1, f_stat1_err, f_stat1_err, f_stat1_err, f_stat1_msg5},
	{f_stat2_err, f_stat2_err, f_stat2_err, f_stat2_msg3, f_stat2_err, f_stat2_msg5},
	{f_stat3_err, f_stat3_err, f_stat3_err, f_stat3_msg3, f_stat3_err, f_stat3_msg5},
	//{f_stat4_nan, f_stat4_nan, f_stat4_nan, f_stat4_nan, f_stat4_nan, f_stat4_nan}
};

int
main(int argc, char *argv[])
{
	int datalen;
	in_port_t port = strtol(DHCP_PORT, NULL, 10);	// source port number
	struct sockaddr_in myskt;	// socket address of the server
	struct dhcph msg;	// message packet
	FILE *fp;	// config-file file pointer
	char ipbuf[BUF_LEN];
	struct client_entry *cli;
	char *address;
	char *netmask;
	fd_set mask;
	int width;
	int prev_stat;

	if (argc != 2) {
		fprintf(stderr, "Usage: ./mydhcpd config-file\n");
		exit(1);
	}

	// initialize lists
	ip_head.fp = ip_head.bp = &ip_head;
	client_head.fp = client_head.bp = &client_head;
	timeout_head.fp = timeout_head.bp = &timeout_head;
	timeout_head.tout_fp = timeout_head.tout_bp = &timeout_head;
	timeout_head.exp_time = 0;
	memset(&msg, 0, sizeof(msg));

	/*
	printf("%d, %d, %d\n", timeout_head.tout_fp->exp_time,
		timeout_head.tout_fp->tout_fp->exp_time, timeout_head.exp_time);
	printf("%d\n", timeout_head.tout_fp->exp_time);
	*/

	// read config-file
	// make IP address and netmask management list
	if ((fp = fopen(argv[1], "r")) == NULL) {
		fprintf(stderr, "cannot open file\n");
		exit(1);
	}
	while (fgets(ipbuf, sizeof(ipbuf), fp) != NULL) {
		struct ip_entry *tmp;
		address = strtok(ipbuf, " \t\n");
		netmask = strtok(NULL, " \t\n");
		if ((tmp = malloc(sizeof(struct ip_entry))) == NULL) {
			fprintf(stderr, "cannot allocate memory\n");
			exit(1);
		}
		strncpy(tmp->address, address, BUF_LEN);
		strncpy(tmp->netmask, netmask, BUF_LEN);
		insert_ip(ip_head.bp, tmp);
	}
		/*
		// print list of IP address and netmask
		struct ip_entry *p;
		for (p = ip_head.fp; p != &ip_head; p = p->fp) {
			printf("IP: %s\tnetmask: %s\n", p->address, p->netmask);
		}
		*/

	// make a socket (UDP)
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}

	// socket setting
	memset(&myskt, 0, sizeof(myskt)); // 0 clear
	myskt.sin_family = AF_INET;	// IPv4
	myskt.sin_port = htons(port);	// port number
	myskt.sin_addr.s_addr = htonl(INADDR_ANY);	// any connection is ok

	// set port number to the socket
	if (bind(sock, (struct sockaddr *)&myskt, sizeof(myskt)) < 0) {
		perror("bind");
		exit(1);
	}

	fprintf(stderr, "waiting for connection ...\n\n");

	for (;;) {
		// set signal handler (SIGALRM)
		if (signal(SIGALRM, alrm_func) == SIG_ERR) {
			perror("signal");
			exit(1);
		}

		// make mask for select()
		FD_ZERO(&mask);	// clear mask
		FD_SET(sock, &mask);	// set discripter to the mask
		width = sock + 1;

		switch (select(width, &mask, NULL, NULL, NULL)) {
		case -1:
			//perror("select");
			//exit(1);
			break;
		case 0:
			// time-out
			fprintf(stderr, "undefined behabior: time-out\n");
			exit(1);
		default:
			// ready state
			if (FD_ISSET(sock, &mask)) {
				// receive data from a client
				if ((datalen = recvfrom(sock, (char *)&msg, sizeof(msg),
							0, (struct sockaddr *)&skt, &sktlen)) < 0) {
					perror("recvfrom");
					exit(1);
				}
				if ((cli = search_client(skt.sin_addr)) == NULL) {
					// IP address is not found at the client list
					// register the client and initialize
					struct client_entry *tmp;
					if ((tmp = malloc(sizeof(struct client_entry))) == NULL) {
						fprintf(stderr, "cannot allocate memory\n");
						exit(1);
					}
					tmp->stat = SSTAT_WAIT_DSC;
					tmp->alloc_addr.s_addr = 0;
					tmp->netmask = 0;
					tmp->cli_addr = skt.sin_addr;
					tmp->cli_port = ntohs(skt.sin_port);
					insert_client(client_head.bp, tmp);
					cli = tmp;
					printf("regist new client: IP address -- %s\n", inet_ntoa(cli->cli_addr));
				} else {
					// IP address is found at the client list
					fprintf(stderr, "This client already exist in client management list\n");
				}

				/*
				struct client_entry *tmp2;
				for (tmp2 = client_head.fp; tmp2 != &client_head; tmp2 = tmp2->fp) {
					printf("client table: IP address -- %s\n", inet_ntoa(tmp2->cli_addr));
				}
				*/

				printf("\n<<");
				print_sstat(cli->stat);
				printf(">>\n");
				prev_stat = cli->stat;
				show_dhcph_recv(&msg);
				// the server processing
				// printf("cli->stat: %d, msg.type: %d\n", cli->stat, msg.type);
				functab[cli->stat][msg.type](cli, &msg);
				show_sstat_trans(prev_stat, cli->stat);
				if (cli->stat == SSTAT_END) {
					f_stat4_nan(cli, &msg);
				}
			}
		}
	}
	close(sock);
	return 0;
}


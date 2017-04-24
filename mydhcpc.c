#include "mydhcp.h"

int stat;	// current status of the client
int prev_stat; // previous status of the client
int alrm_flag = 0;
struct dhcph msg;	// DHCP message
struct addrinfo hints, *res;	// socket address of the client
int sock;	// socket descripter

void
cstat_end(int signo)
{
	fprintf(stderr, "\n");
	//if (stat == CSTAT_GET_IP) {
	prev_stat = stat;
	stat = CSTAT_END;
		/*
		if (prev_stat != stat) {
			show_cstat_trans(prev_stat, stat);
		}
		*/
	//} else {
	//	fprintf(stderr, "\n");
	//	exit(1);
	//}
	set_dhcph(&msg, DHCPRELEASE, CODE_OK/* 0 */, 0, msg.address, 0);
	if (sendto(sock, (char *)&msg, sizeof(msg), 0,
			res->ai_addr, res->ai_addrlen) < 0) {
				perror("sendto");
				exit(1);
	}
	show_dhcph_send(&msg);
	close(sock);
	exit(0);
}

void
alrm_func(int signo)
{
	if (stat == CSTAT_GET_IP) {
		fprintf(stderr, "half of TTL has passed\n");
		prev_stat = stat;
		stat = CSTAT_WAIT_ACK;
		/*
		if (prev_stat != stat) {
			show_cstat_trans(prev_stat, stat);
		}
		*/
		alrm_flag = 1;
	} else {
		fprintf(stderr, "undefined behavior\n");
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int datalen;
	struct sockaddr_in skt;	// socket address of the server
	socklen_t sktlen = sizeof(skt);
	char host[BUF_LEN];
	char *serv;
	int err;
	serv = DHCP_PORT;	// destination port number
	struct timeval timeout;	// TIMEOUT
	struct itimerval timer;	// TTL
	fd_set mask;
	int width;
	int alloc_flag = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: ./mydhcpc server-IP-address\n");
		exit(1);
	}

	// initialize client status
	stat = CSTAT_INIT;
	prev_stat = CSTAT_INIT;
	memset(&msg, 0, sizeof(msg));

	if (strlen(argv[1]) > BUF_LEN - 1) {
		fprintf(stderr, "host name is too many\n");
		exit(1);
	} else {
		// set host name of the server
		strncpy(host, argv[1], BUF_LEN - 1);
		host[strlen(host)] = '\0';
	}

	// initialize
	memset(&hints, 0, sizeof(hints));	// clear hints
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_DGRAM;	// UDP
	hints.ai_protocol = 0;

	if ((err = getaddrinfo(host, serv, &hints, &res)) < 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		exit(1);
	}

	// make a socket
	if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		perror("socket");
		exit(1);
	}

	memset(&timer, 0, sizeof(timer));	// clear timer



	for (;;) {
		// set signal handler (SIGINT)
	if (signal(SIGINT, cstat_end) == SIG_ERR) {
		perror("signal");
		exit(1);
	}	// set signal handler (SIGALRM)
		if (signal(SIGALRM, alrm_func) == SIG_ERR) {
			perror("signal");
			exit(1);
		}

		// set time-out value for select()
		timeout.tv_sec = TIMEOUT;
		timeout.tv_usec = 0;

		// set interval timer value
		timer.it_value.tv_sec = TTL / 2;
		timer.it_value.tv_usec = 0;

		// make mask for select()
		FD_ZERO(&mask);	// clear mask
		FD_SET(sock, &mask);	// set discripter to the mask
		width = sock + 1;

		// print current client state
		printf("<<");
		print_cstat(stat);
		printf(">>\n");

		switch (stat) {
		case CSTAT_INIT:
			// send DHCPDISCOVER
			set_dhcph(&msg, DHCPDISCOVER, CODE_OK/* 0 */, 0, 0, 0);
			// send data to the server
			if (sendto(sock, (char *)&msg, sizeof(msg), 0,
						res->ai_addr, res->ai_addrlen) < 0) {
				perror("sendto");
				exit(1);
			}
			show_dhcph_send(&msg);
			prev_stat = stat;
			stat = CSTAT_WAIT_OFFER;
			//show_cstat_trans(prev_stat, stat);
			break;
		case CSTAT_WAIT_OFFER:
			/*
			// set time-out value for select()
			timeout.tv_sec = TIMEOUT;
			timeout.tv_usec = 0;
			*/
			switch (select(width, &mask, NULL, NULL, &timeout)) {
			case -1:
				perror("select");
				exit(1);
			case 0:
				// time-out
				fprintf(stderr, "\ntime-out 10 seconds\n\n");
				prev_stat = stat;
				stat = CSTAT_INIT;
				//show_cstat_trans(prev_stat, stat);
				break;
			default:
				// ready state
				if (FD_ISSET(sock, &mask)) {
					// receive data from the server
					if ((datalen = recvfrom(sock, (char *)&msg, sizeof(msg), 0,
									(struct sockaddr *)&skt, &sktlen)) < 0) {
						perror("recvfrom");
						exit(1);
					}
					show_dhcph_recv(&msg);
					if (msg.type == DHCPOFFER) {
						switch (msg.code) {
						case CODE_OK:	/* 0 */
							set_dhcph(&msg, DHCPREQUEST, CODE_REQ_ASSIGN/* 10 */,
									TTL, msg.address, msg.netmask);
							if (sendto(sock, (char *)&msg, sizeof(msg), 0,
									res->ai_addr, res->ai_addrlen) < 0) {
								perror("sendto");
								exit(1);
							}
							show_dhcph_send(&msg);
							prev_stat = stat;
							stat = CSTAT_WAIT_ACK;
							//show_cstat_trans(prev_stat, stat);
							break;
						case CODE_OFFER_ERR: /* 129 */
							prev_stat = stat;
							stat = CSTAT_INIT;
							//show_cstat_trans(prev_stat, stat);
							break;
						default:
							fprintf(stderr, "undefined code\n");
							exit(1);
						}
					} else {
						fprintf(stderr, "undefined message type\n");
						exit(1);
					}
				}
				break;
			}
			break;
		case CSTAT_WAIT_ACK:
			if (alrm_flag) {
				alrm_flag = 0;
				fprintf(stderr, "exend the time to use IP address\n");
				set_dhcph(&msg, DHCPREQUEST, CODE_REQ_EXTENSION/* 11 */, TTL,
						msg.address, msg.netmask);
				if (sendto(sock, (char *)&msg, sizeof(msg), 0,
						res->ai_addr, res->ai_addrlen) < 0) {
					perror("sendto");
					exit(1);
				}
				show_dhcph_send(&msg);
			}
			/*
			// set time-out value for select()
			timeout.tv_sec = TIMEOUT;
			timeout.tv_usec = 0;
			*/
			switch (select(width, &mask, NULL, NULL, &timeout)) {
			case -1:
				printf("SIGINT");
				perror("select");
				exit(1);
				break;
			case 0:
				// time-out
				fprintf(stderr, "time-out 10 seconds\n");
				prev_stat = stat;
				stat = CSTAT_INIT;
				//show_cstat_trans(prev_stat, stat);
				break;
			default:
				// ready
				if (FD_ISSET(sock, &mask)) {
					// recerive data from the server
					if ((datalen = recvfrom(sock, (char *)&msg, sizeof(msg), 0,
								(struct sockaddr *)&skt, &sktlen)) < 0) {
						perror("recvfrom");
						exit(1);
					}
					show_dhcph_recv(&msg);
					if (msg.type == DHCPREPLY) {
						switch (msg.code) {
						case CODE_OK:	/* 0 */
							prev_stat = stat;
							stat = CSTAT_GET_IP;
							if (alloc_flag++ == 0) {
								// if I convert, then seg error
								//printf("Time to Live: %u\n", msg.ttl);
								//printf("IP address  : %s\n", convert_addr(msg.address));
								//printf("netmask     : %s\n", convert_addr(msg.netmask));
								show_get_ip(&msg);
							}
							break;
						case CODE_REPLY_ERR: /* 130 */
							prev_stat = stat;
							stat = CSTAT_INIT;
							//show_cstat_trans(prev_stat, stat);
							break;
						default:
							fprintf(stderr, "undefined code\n");
							exit(1);
						}
					} else {
						fprintf(stderr, "undefined message type\n");
						exit(1);
					}
				}
				break;
			}
			break;
		case CSTAT_GET_IP:
			// make intarval timer
			if (setitimer(ITIMER_REAL, &timer, NULL) < 0) {
				perror("setitimer");
				exit(1);
			}
			timer.it_value.tv_sec = TTL / 2;
			timer.it_value.tv_usec = 0;
			pause();
			break;
		case CSTAT_END:
			set_dhcph(&msg, DHCPRELEASE, CODE_OK/* 0 */, 0, msg.address, 0);
			if (sendto(sock, (char *)&msg, sizeof(msg), 0,
					res->ai_addr, res->ai_addrlen) < 0) {
				perror("sendto");
				exit(1);
			}
			show_dhcph_send(&msg);
			close(sock);
			return 0;
		default:
			fprintf(stderr, "undefined status\n");
			exit(1);
		}
		if (prev_stat != stat) {
			show_cstat_trans(prev_stat, stat);
		}
	}
}


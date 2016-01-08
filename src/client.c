/*
 * client.c --
 *
 *  Examples of use of pktd daemon
 *
 * Copyright (c) 2001-2002 The International Computer Science Institute
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * A. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * B. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * C. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */



#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>


/* you must include wire.h */
#include "wire.h"


/* include lstdio.h if you want to use user-buffered writing */
#include "lstdio.h"


/* wire_errcode is a global variable used to report errors */
extern int wire_errcode;

/* error-to-string procedure */
extern const char *wire_err_msg(int errcode);



/* the example being run */
int example_mode = 0;


/* lstdio's FILE pointer used for user-buffered writing (instead of 
 * stdio's FILE*) */
lFILE *fp;

#define MAXBUFFER 1024
/* tcpdump's filter expression (e.g. "tcp port 80") */
char filter[MAXBUFFER];
/* bytes of data that will be snarfed from each packet */
int snaplen;


#define CLIENT_WAITING_TIME 2



/* writing mode. You can choose: 
 *	- daemon writing (W_DW)
 *	- local writing (W_LW)
 *	- callback processing (default)
 *
 *	More flags:
 *	- whether the daemon must immediate delivery traffic or buffer it (for 
 *		performance reasons): W_ID
 *	- whether the daemon must compress the packets: W_CO
 *	- whether libwire will keep the packet compressed: W_KC
 */
int mode;

char filename[MAXBUFFER];


/*
#define HP_FILTER "host bosshog.lbl.gov and host bmrc.berkeley.edu and not icmp"
*/
#define HP_FILTER "host bosshog.lbl.gov and host swift.nersc.gov and not icmp"


/* the callback function being called per packet */
int packet_callback (const u_char *pkt, struct timeval ts, int len, 
		int caplen, void *user_data);

void parse_args (int argc, char **argv);
void usage (char **argv);
int example_1();
int example_2(int compress);
int example_3();



/*
 * main
 *
 *	Main procedure. Sets default values, parses arguments from command line, 
 *	and calls the different examples. 
 *
 */
int main (int argc, char **argv)
{

	/* set default values */
	snaplen = 68;
	sprintf (filename, "/tmp/default-client.bin");
	mode = 0;


	parse_args (argc, argv);


	switch (example_mode) {
		case 1:
			return example_1();
			break;
		case 2:
			return example_2(0);
			break;
		case 3:
			sprintf (filename, "data-client%%d.bin");
			return example_3();
			break;
		case 4:
			return example_2(1);
			break;
		case 5:
			return example_2(2);
			break;
		default:
			usage(argv);
			break;
	}

	exit (0);
}




/*
 * example_3
 *
 * example_3 shows how to access to the pktd daemon in order to achieve 
 * highest-performance packet capturing. 
 *
 */
int example_3 ()
{
	/* pktd connection descriptor */
	pktd_t *pdd;

	/* pcap statistics structure */
	struct pcap_stat stat;

	/* other variables */
	int result;
	struct timeval timeout;

	/* checkpointing description */
	cp_t cp;

	/* checkpoint time (seconds)
	 * Sets the time after which the daemon will open a new file to keep 
	 * dumping packets. 
	 * cp.time == 0 means no limit */
	cp.time = 0;

	/* checkpoint length (KB)
	 * Sets the maximum length of files. When reached, the daemon will open 
	 * a new file to keep dumping packets. 
	 * cp.length == 0 means no limit */
	cp.length = 0;

	/* checkpoint maximum files (number)
	 * Sets the maximum number of files the daemon may open before closing 
	 * the connection.
	 * cp.files == 0 means no limit */
	cp.files = 0;

	mode = W_DW; /* daemon-writing processing */
	mode &= ~W_ID; /* reset immediate delivery flag */

	sprintf (filter, HP_FILTER);

	/* init the wire and add the filter */
	printf ("wire_init (mode 0x%02x, filter = \"%s\", snaplen = %i)\n", 
			mode, filter, snaplen);

	/* packet processing done by the daemon (daemon writing) */
	if ((pdd = wire_init (filter, snaplen, mode, &cp, NULL, NULL, 
			filename)) == NULL) {
		/* perror ("wire_init()"); */
		printf ("wire_init(): %s\n", wire_err_msg(wire_errcode));
		exit (1);
	}

	printf ("Data will be dumped on %s\n", filename);


	/* get as many packets as possible for 10 seconds */
	timeout.tv_sec = 10L;
	timeout.tv_usec = 0L;
	/* wait for the timeout to go away */
	if ((result = select (1, NULL, NULL, NULL, &timeout)) < 0) {
		perror ("select()");
	}

	/* close the wire */
	printf ("wire_done ()\n");
	(void)wire_done (pdd, &stat);
	printf ("statistics -> recv: %d, drop: %d, ifdrop: %d\n", 
			stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);

	exit (0);
}




/*
 * example_2
 *
 * example_2 shows how to access to the pktd daemon in order to achieve 
 * high-performance packet capturing. 
 *
 */
int example_2 (int compress)
{
	/* pktd connection descriptor */
	pktd_t *pdd;

	/* user data
	 * Any data that needs to be passed to the per-packet callback must be 
	 * referenced by this variable. You can cast it at your own will */
	int *user_data;

	/* file descriptor set
	 * In case you need to listen to several descriptors at the same time */
	fd_set fds;

	/* total number of packets */
	int total = 0;

	/* pcap statistics structure */
	struct pcap_stat stat;

	/* other variables */
	int result;
	struct timeval timeout;
	int flush_done = 0;

	/* checkpointing description */
	cp_t cp;

	/* compression description */
	co_t co;

	/* checkpoint time (seconds)
	 * Sets the time after which the daemon will open a new file to keep 
	 * dumping packets. 
	 * cp.time == 0 means no limit */
	cp.time = 0;

	/* checkpoint length (KB)
	 * Sets the maximum length of files. When reached, the daemon will open 
	 * a new file to keep dumping packets. 
	 * cp.length == 0 means no limit */
	cp.length = 0;

	/* checkpoint maximum files (number)
	 * Sets the maximum number of files the daemon may open before closing 
	 * the connection.
	 * cp.files == 0 means no limit */
	cp.files = 0;

	/* compression mask
	 * Sets the mask used in the compression
	 */
	co.ip_mask = DEFAULT_PKTD_COMPRESSION_IP_MASK;
	co.tcp_mask = DEFAULT_PKTD_COMPRESSION_TCP_MASK;
	co.udp_mask = DEFAULT_PKTD_COMPRESSION_UDP_MASK;

	/* compression restart marker offset
	 * Sets the restart marker offset used in the compression
	 */
	co.rm_offset = DEFAULT_PKTD_COMPRESSION_RESTART_MARKER;


	mode = 0; /* callback processing */
	mode &= ~W_ID; /* reset immediate delivery flag */

	if (compress == 1) {
		/* set compress flag */
		mode |= W_CO;
	} else if (compress == 2) {
		/* set compress flag */
		mode |= W_CO;
		/* set keep compressed flag */
		mode |= W_KC;
	}

	sprintf (filter, HP_FILTER);

	/* open the filename where the packets will be dumped using the 
	 * provided user-buffered library (check lstdio.h).
	 * If you want to use a socket instead of a file descriptor, open the 
	 * socket with socket(2), and then map the descriptor with a lFILE* 
	 * with lfdopen()
	 */
	printf ("Writing data to file %s\n", filename);
	if ((fp = lfopen (filename, 8192)) == NULL) {
		printf ("client: cannot open file %s\n", filename);
		exit (1);
	}


	/* init the wire and add the filter */
	printf ("wire_init (mode 0x%02x, filter = \"%s\", snaplen = %i)\n", 
			mode, filter, snaplen);

	/* packet processing done by the client callback (buffered writing) */
	if ((pdd = wire_init (filter, snaplen, mode, &cp, &co, NULL, NULL)) == NULL) {
		/* perror ("wire_init()"); */
		printf ("wire_init(): %s\n", wire_err_msg(wire_errcode));
		exit (1);
	}

	printf ("Data will be dumped on %s\n", filename);

	/* write the tcpdump header */
	if (pktd_lfwrite_ext_header (fp, pdd->snaplen, pdd->datalink, &pdd->co, 
			pdd->filter) < 0) {
		printf ("client: couldn't write tcpdump header\n");
		exit (1);
	}


	/* get as many packets as possible */

	/* user_data points to the header size */
	user_data = &pdd->hdr_size;

	while (1) {
		/* reset the file descriptor set */
		FD_ZERO (&fds);

		/* add the daemon as one of the descriptor in the set */
		(void)wire_add_fds (pdd, &fds);

		timeout.tv_sec = CLIENT_WAITING_TIME;
		timeout.tv_usec = 0L;
		/* wait for activity in any of the file descriptors */
		if ((result = select (1+wire_max_fd(pdd), &fds, NULL, NULL, &timeout)) < 0) {
			perror ("select()");
		}


		if (result == 0) {
			/* timeout */
			if (flush_done == 0) {
				wire_flush (pdd);
				flush_done = 1;
			} else {
				break;
			}
		}

		if (wire_is_set (pdd, &fds)) {

			result = wire_activity(pdd, &fds, packet_callback, (void *)user_data);
			if (result == -1) {
				printf ("EOF in the data socket\n");
				lfflush (fp);
				break;
			} else if (result == -2) {
				printf ("client.c: Error in the data socket\n");
				exit(1);
			} else {
				/* we got a packet from the daemon */
				total += result;
			}

		}
	}


	/* close the wire */
	printf ("wire_done ()\n");
	(void)wire_done (pdd, &stat);
	printf ("statistics -> recv: %d, drop: %d, ifdrop: %d\n", 
			stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);

	lfflush (fp);
	lfclose (fp);

	exit (0);
}




/* packet injection variable and procedure */
int packet_injection_requested;
int inject_packet(pktd_t *pdd);
int libnet_in_cksum(u_short *addr, int len);
/* from libnet/include/libnet/libnet-macros.h */
#define LIBNET_CKSUM_CARRY(x) \
		(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))






/*
 * example_1
 *
 *	example_1 shows an interactive example of pktd daemon access. 
 *	The client requests receiving 5 HTTP packets, changes the filter, 
 *	receives 5 more packets, and then exits. 
 *
 */
int example_1 (int argc, char **argv)
{
	/* pktd connection descriptor */
	pktd_t *pdd;

	fd_set fds;
	int *user_data;

	int total = 0;
	struct pcap_stat stat;

	/* checkpointing description */
	cp_t cp;
	cp.time = 0; /* seconds, == 0 means no limit */
	cp.length = 0; /* maximum length of files in KB, == 0 means no limit */
	cp.files = 0; /* files, ==0 means no limit */

	/* don't inject a packet by default */
	packet_injection_requested = 0;


	sprintf (filter, "tcp port 80");


	/* init the wire and add the filter */
	printf ("wire_init (mode 0x%02x, filter = \"%s\", snaplen = %i)\n", 
			mode, filter, snaplen);

	if ((mode & W_DW) != 0) {
		/* packet processing done by the client callback (immediate writing) */
		mode |= W_ID; /* set immediate delivery flag */

		if ((pdd = wire_init (filter, snaplen, mode, &cp, NULL, NULL, NULL)) == 
				NULL) {
			/* perror ("wire_init()"); */
			printf ("wire_init(): %s\n", wire_err_msg(wire_errcode));
			exit (1);
		}

	} else {
		/* packet processing done by the daemon (buffered writing) */
		mode &= ~W_ID; /* reset immediate delivery flag */
		if ((pdd = wire_init (filter, snaplen, mode, &cp, NULL, NULL, filename)) == 
				NULL) {
			/* perror ("wire_init()"); */
			printf ("wire_init(): %s\n", wire_err_msg(wire_errcode));
			exit (1);
		}

		if ((mode & W_DW) != 0) {
			printf ("Data will be dumped on %s\n", pktd_prot_file_path);
			/* we just exit! The daemon will respect the cp variable */
			exit (0);
		} else {
			printf ("Data will be dumped on %s\n", filename);
		}
	}

	/* get some packets */

	/* user_data points to the header size */
	user_data = &pdd->hdr_size;

	while (1) {
		/* reset the file descriptor set */
		FD_ZERO (&fds);

		/* add the daemon as one of the descriptor in the set */
		(void)wire_add_fds (pdd, &fds);

		/* wait for activity in any of the file descriptors */
		if (select (1+wire_max_fd(pdd), &fds, NULL, NULL, NULL) < 0) {
			perror ("select()");
		}

		if (wire_activity(pdd, &fds, packet_callback, (void *)user_data) < 0) {
			printf ("error in the data socket\n");
			exit(1);
		} else {
			/* we got a packet from the daemon */
			total ++;
			if (total == 5) {
				struct pcap_stat stat;
				if (packet_injection_requested == 1) {
					if (inject_packet(pdd) != 0) {
						printf ("inject_packet(): %s\n", wire_err_msg(pdd->wire_errcode));
					}
				}

				/* change the filter */
				printf ("wire_setfilter (%s)\n", "tcp port 79");
				wire_setfilter (pdd, "tcp port 79", &cp);
				wire_stats (pdd, &stat);
				printf ("The stats are: %i, %i, %i\n", stat.ps_recv, stat.ps_drop,
						stat.ps_ifdrop);
			} else if (total > 10) {
				break;
			}
		}
	}


	/* close the wire */
	printf ("wire_done ()\n");
	(void)wire_done (pdd, &stat);
	printf ("statistics -> recv: %d, drop: %d, ifdrop: %d\n", 
			stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);

	exit (0);
}




/*
 * packet_callback
 *
 *	Callback function. It is called whenever a packet is received
 *
 * Inputs:
 *	- pdd: the pktd connection descriptor
 *	- pkt: a pointer to the packet
 *	- ts: the time when the packet was received
 *	- len: the original packet length
 *	- caplen: the captured packet length. This is pkt length
 *	- user_data: the header size
 *
 * Output:
 *	- return: 1 always
 *
 */
int packet_callback (const u_char *pkt, struct timeval ts, int len, 
		int caplen, void *user_data)
{
	int i = 0;
	int hdr_size = *(int *)user_data;

	char packet_header[TCPDUMP_PACKET_HEADER_LENGTH];

	/* prepare the packet header */
	*(long *)(packet_header+0) = htonl(ts.tv_sec);
	*(long *)(packet_header+4) = htonl(ts.tv_usec);
	*(u_int32_t *)(packet_header+8) = htonl(caplen);
	*(u_int32_t *)(packet_header+12) = htonl(len);

	
	switch (example_mode) {
		case 1:
			/* print the packet network header in a tcpdump fashion */
			i += hdr_size;
			printf ("%li.%06li ", ts.tv_sec, ts.tv_usec);
			printf ("%i.%i.%i.%i:%i > %i.%i.%i.%i:%i ",
					(int)*(pkt+i+12), (int)*(pkt+i+13), (int)*(pkt+i+14), (int)*(pkt+i+15),
					(int)ntohs(*(u_short *)(pkt+i+ 4 * (int)((*(pkt+i+0))&0xf) )),
					(int)*(pkt+i+16), (int)*(pkt+i+17), (int)*(pkt+i+18), (int)*(pkt+i+19),
					(int)ntohs(*(u_short *)(pkt+i+2+ 4 * (int)((*(pkt+i+0))&0xf) )));
			printf ("(%i/%i)\n", caplen, len);
			break;

		case 2:
		case 4:
			/* dump data to disk */
			if ((lfwrite (fp, packet_header, TCPDUMP_PACKET_HEADER_LENGTH) < 
					TCPDUMP_PACKET_HEADER_LENGTH) ||
					(lfwrite (fp, (void*)pkt, caplen) < caplen)) {
				printf ("packet_callback(): %s (%d)\n", sys_errlist[errno], errno);
				exit (1);
			}
			break;

		case 5:
			/* dump compressed data to disk */
			if (lfwrite (fp, (void*)pkt, len) < len) {
				printf ("packet_callback(): %s (%d)\n", sys_errlist[errno], errno);
				exit (1);
			}
			break;

		default:
			break;
	}

	return 1;
}




/*
 * usage
 *
 * A simple usage method
 *
 * Inputs:
 *	- argv: arguments
 *
 * Outputs:
 *
 */
void usage (char **argv)
{
	fprintf (stderr, "Usage: %s [options]\n", *argv);
	fprintf (stderr, "  -h\t\t\tShow this information\n");
	fprintf (stderr, "  -V\t\t\tDisplay pktd version number only\n");
	fprintf (stderr, "  -s [snaplen]\tRequest a specific snaplen\n");
	fprintf (stderr, "  -1\t\t\tRun example 1\n");
	fprintf (stderr, "    -D\t\t\tUse daemon writing\n");
	fprintf (stderr, "    -L\t\t\tUse local writing\n");
	fprintf (stderr, "    -I\t\t\tInject a packet\n");
	fprintf (stderr, "  -2\t\t\tRun example 2\n");
	fprintf (stderr, "  -3\t\t\tRun example 2\n");
	fprintf (stderr, "\n");
	fprintf (stderr, "Example 1:\n");
	fprintf (stderr, "   1. set filter to \"tcp port 80\"\n");
	fprintf (stderr, "   2. get 5 packets\n");
	fprintf (stderr, "   3. if '-I', inject an ICMP packet\n");
	fprintf (stderr, "   4. switch filter to \"tcp port 79\"\n");
	fprintf (stderr, "   5. get 5 packets\n");
	fprintf (stderr, "   6. exit\n");
	fprintf (stderr, "Example 2:\n");
	fprintf (stderr, "   1. set filter to \"%s\"\n", HP_FILTER);
	fprintf (stderr, "   2. get as many packets as possible\n");
	fprintf (stderr, "   3. after %i seconds w/o packets, exit cleanly\n", 
			CLIENT_WAITING_TIME);
	fprintf (stderr, "Example 3:\n");
	fprintf (stderr, "   1. set filter to \"%s\". Request daemon-writing\n", HP_FILTER);
	fprintf (stderr, "   2. wait for 10 seconds\n");
	fprintf (stderr, "   3. exit cleanly\n");
	fprintf (stderr, "Example 4:\n");
	fprintf (stderr, "   Example 2 using trace compression and decompression\n");
	fprintf (stderr, "Example 5:\n");
	fprintf (stderr, "   Example 2 using only trace compression\n");
}




/*
 * parse_args
 *
 * Parse command line for options
 *
 * Inputs:
 *	- argc: argument counter
 *	- argv: arguments
 *
 * Outputs:
 *
 */
void parse_args (int argc, char **argv)
{
	int arg;
	extern char *optarg;
	extern int optind;
	extern int opterr;

	/* the arguments to options must be separated by white-space. */
	opterr = 0;
	while ((arg = getopt(argc, argv, "12345DLs:VIh?")) != -1) {
		switch (arg) {
			case '1':
				example_mode = 1;
				break;

			case '2':
				example_mode = 2;
				break;

			case '3':
				example_mode = 3;
				break;

			case '4':
				example_mode = 4;
				break;

			case '5':
				example_mode = 5;
				break;

			case 'D':
				mode |= W_DW;
				break;

			case 'L':
				mode |= W_LW;
				break;

			case 's':
				snaplen = atoi(optarg);
				break;

			case 'I':
				packet_injection_requested = 1;
				break;

			case 'V':
				/* dump version number and exit */
				fprintf (stderr, "Example client for pktd %s\n", pktd_version);
				exit(0);
				break;

			case 'h':
			default:
				usage (argv);
				exit(1);
				break;
		}
	}

	return;
}



int inject_packet(pktd_t *pdd)
{
	u_char ip[1024];
	short length;
	u_int32_t ip_src;
	u_int32_t ip_dst;
	int sum;

	/* build a simple ping packet */
	printf ("requesting injection of a simple ping packet (ICMP/IP)\n");

	/* build the ip header */
	*(ip+0) = 0x40; /* version 4 */
	*(ip+0) |= 0x05; /* 20 byte header */
	*(ip+1) = 0; /* type of service */
	*(short *)(ip+4) = htons(0); /* identification */
	*(short *)(ip+6) = htons(0x4000); /* fragmentation */
	*(ip+8) = 64; /* ttl */
	*(ip+9) = IPPROTO_ICMP; /* protocol */
	*(short *)(ip+10) = htons(0); /* checksum */

	/* IP source and destination addresses */
	ip_src = ((u_int32_t)169)<<24; /* elmer.bmrc.berkeley.edu */
	ip_src |= ((u_int32_t)229)<<16;
	ip_src |= ((u_int32_t)12)<<8;
	ip_src |= ((u_int32_t)122)<<0;
	ip_dst = ((u_int32_t)192)<<24; /* marmot.aciri.org */
	ip_dst |= ((u_int32_t)150)<<16;
	ip_dst |= ((u_int32_t)187)<<8;
	ip_dst |= ((u_int32_t)39)<<0;
	*(u_int32_t *)(ip+12) = htonl(ip_src); /* source address */
	*(u_int32_t *)(ip+16) = htonl(ip_dst); /* destination address */
	length = 20;
	
	/* build the ICMP payload header */
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
	*(ip+length+0) = ICMP_ECHO; /* type */
	*(ip+length+1) = 0; /* code */
	*(short *)(ip+length+2) = htons(0); /* checksum  */
	*(short *)(ip+length+4) = htons(0x0421); /* identifier */
	*(short *)(ip+length+6) = htons(0); /* sequence number */
	*(short *)(ip+length+8) = htons(0xffff); /* some data */
	*(short *)(ip+length+10) = htons(0xffff); /* some data */
	/* checksum (already in network order) */
	sum = libnet_in_cksum((u_short*)(ip+length), 12);
	*(short *)(ip+length+2) = LIBNET_CKSUM_CARRY(sum);

	/* finish the ip header */
	*(short *)(ip+2) = htons(length+12); /* packet length */
	/* checksum (already in network order) */
	sum = libnet_in_cksum((u_short*)ip, length);
	*(short *)(ip+10) = LIBNET_CKSUM_CARRY(sum);

	/* inject the packet */
	return wire_inject (pdd, ip);
}


/* from libnet/src/libnet_checksum.c */
int libnet_in_cksum(u_short *addr, int len)
{
	int sum;
	int nleft;
	u_short ans;
	u_short *w;

	sum = 0;
	ans = 0;
	nleft = len;
 	w = addr;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(u_char *)(&ans) = *(u_char *)w;
		sum += ans;
	}
	return (sum);
}



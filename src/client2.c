/*
 * client2.c --
 *
 *  Example of use of PCAPD daemon
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
#include "lstdio.h"

/* errcode global variable */
extern int wire_errcode;

/* error-to-string procedures */
extern const char *wire_err_msg(int errcode);

/* version number */
#include "version.h"
extern char pcapd_version[];

void parse_args (int argc, char **argv, int* snaplen, char *pattern);


lFILE * fp;



/*
 * my_callback
 *
 *	Callback function. It is called whenever a packet is received
 *
 * Inputs:
 *	- pdd: the pcapd connection descriptor
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
int my_callback (const u_char *pkt, struct timeval ts, int len, 
		int caplen, void *user_data)
{
/*
	int i = 0;
	int hdr_size = *(int *)user_data;
*/

	char packet_header[TCPDUMP_PACKET_HEADER_LENGTH];

	/* prepare the packet header */
	*(long *)(packet_header+0) = htonl(ts.tv_sec);
	*(long *)(packet_header+4) = htonl(ts.tv_usec);
	*(u_int32_t *)(packet_header+8) = htonl(caplen);
	*(u_int32_t *)(packet_header+12) = htonl(len);

	
	/* dump data to disk */
	if ((lfwrite (fp, packet_header, TCPDUMP_PACKET_HEADER_LENGTH) < 
			TCPDUMP_PACKET_HEADER_LENGTH) ||
			(lfwrite (fp, pkt, caplen) < caplen)) {
		printf ("my_callback(): %s (%d)\n", sys_errlist[errno], errno);
		exit (1);
	}

#if 0
	/* currently we just print the packet network header in a tcpdump fashion */
	i += hdr_size;
	printf ("%li.%06li ", ts.tv_sec, ts.tv_usec);
	printf ("%i.%i.%i.%i:%i > %i.%i.%i.%i:%i ",
			(int)*(pkt+i+12), (int)*(pkt+i+13), (int)*(pkt+i+14), (int)*(pkt+i+15),
			(int)ntohs(*(u_short *)(pkt+i+ 4 * (int)((*(pkt+i+0))&0xf) )),
			(int)*(pkt+i+16), (int)*(pkt+i+17), (int)*(pkt+i+18), (int)*(pkt+i+19),
			(int)ntohs(*(u_short *)(pkt+i+2+ 4 * (int)((*(pkt+i+0))&0xf) )));
	printf ("(%i/%i)\n", caplen, len);
#endif

	return 1;
}



/*
 * main
 */
int main (int argc, char **argv)
{
#define MAXBUFFER 1024
	char filter[MAXBUFFER];
	char filename[MAXBUFFER];

	/* pcapd connection descriptor */
	pcapd_t *pdd;

	fd_set fds;
	int cp_time = 0; /* seconds, == 0 means no limit */
	int cp_length = 0; /* maximum length of files in KB, == 0 means no limit */
	int cp_files = 0; /* files, ==0 means no limit */
	int snaplen = 68;
	int daemon_writing = 0; /* boolean that indicates daemon writing */
	int *user_data;

	int total = 0;
	struct pcap_stat stat;


	/* this is the filter we are going to install */
	sprintf(filter, "host ncs.lbl.gov and host swift.nersc.gov and not icmp");

	sprintf (filename, "/tmp/default-client2.bin");
	parse_args (argc, argv, &snaplen, filename);
	printf ("Writing data to file %s\n", filename);

	if ((fp = lfopen (filename, 8192)) == NULL) {
		printf ("client2: cannot open file %s\n", filename);
		exit (1);
	}


	/* init the wire and add the filter */
	printf ("wire_init (PORT mode, filter = \"%s\", snaplen = %i)\n", 
			filter, snaplen);

	/* use a port to dump data */
	if ((pdd = wire_init (filter, NULL, snaplen, NULL, NULL, daemon_writing, 
			cp_time, cp_length, cp_files)) == NULL) {
		/* perror ("wire_init()"); */
		printf ("wire_init(): %s\n", wire_err_msg(pdd->wire_errcode));
		exit (1);
	}

	printf ("Data will be dumped on %s\n", filename);

	/* write the tcpdump header */
/*
	Note: this is an horrendous kludge. pcapd sends the Ethernet header 
	to the clients (so datalink == DLT_EN10MB), but these believe the 
	Ethernet header is stripped (datalink == DLT_NULL). I kludge this 
	here because I don't have time to figure out where's the inconsistency. 
	This way things work. 

	BTW, as a second thought, it may be a good idea to strip the Ethernet 
	header at the daemon. Assuming final clients (the ones that will 
	effectively use the packets) are in a different host, the Ethernet 
	header doesn't make sense for them

	if (pcapd_write_header (lfileno(fp), pdd->snaplen, DLT_NULL) < 0) {
*/
	if (pcapd_write_header (lfileno(fp), pdd->snaplen, DLT_EN10MB) < 0) {
		printf ("client2: couldn't write tcpdump header\n");
		exit (1);
	}


	/* get as many packets as possible */

	/* reset the file descriptor set */
	FD_ZERO (&fds);

	/* add the daemon as one of the descriptor in the set */
	(void)wire_add_fds (pdd, &fds);

	/* user_data points to the header size */
	user_data = &pdd->hdr_size;

	while (1) {
		/* wait for activity in any of the file descriptors */
		if (select (1+wire_max_fd(pdd), &fds, NULL, NULL, NULL) < 0) {
			perror ("select()");
		}

		if (wire_activity(pdd, &fds, my_callback, (void *)user_data) < 0) {
			printf ("error in the data socket\n");
			exit(1);
		} else {
			/* we got a packet from the daemon */
			total ++;
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
	fprintf (stderr, "  -h\t\t\tShow this information.\n");
	fprintf (stderr, "  -V\t\t\tDisplay version number only.\n");
	fprintf (stderr, "  -s [snaplen]\tRequest a snaplen\n");
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
 *	- pattern: the file pattern requestd, if so
 *
 */
void parse_args (int argc, char **argv, int *snaplen, 
		char *pattern)
{
	int arg;
	extern char *optarg;
	extern int optind;
	extern int opterr;

	/* the arguments to options must be separated by white-space. */
	opterr = 0;
	while ((arg = getopt(argc, argv, "s:Vh?")) != -1) {
		switch (arg) {

			case 's':
				*snaplen = atoi(optarg);
				break;


			case 'V':
				/* dump version number and exit */
				fprintf (stderr, "Example client for pcapd %s\n", pcapd_version);
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




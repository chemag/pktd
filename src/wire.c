/*
 * wire.c --
 *
 *	PKTD daemon: the client stub. The provided API is VP's wire
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
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "wire.h"
#include "protocol.h"
#include "version.h"
#include "trace-codec.h"


/* file descriptor for logging */
FILE *log_file;


int wire_check_pattern (const char *pattern);
int wire_read_raw_packet (pktd_t *pdd, struct pcap_pkthdr *pkthdr);
int wire_read_and_uncompress_packet (pktd_t *pdd, struct pcap_pkthdr *pkthdr);
int wire_read_compressed_buffer (pktd_t *pdd, struct pcap_pkthdr *pkthdr);


#define ISSET(set,flag) (((set & flag) == 0) ? 0 : 1)




/*
 * wire_set_hdr_size  
 *
 *	Sets the global variable hdr_size with the datalink header size
 *
 * Inputs:
 *	- datalink: datalink type
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
static int wire_set_hdr_size (pktd_t *pdd)
{
	int datalink;
	int result;

	datalink = pcap_datalink(pdd->pd);
	result = pktd_get_hdr_size (datalink);
	if (result < 0) {
		pdd->wire_errcode = WIRE_ERR_LOCAL_UNKNOWN_LINK_TYPE;
		return -1;
	}

	pdd->hdr_size = result;
	return 0;
}




/*
 * set_pcap_filter
 *
 *	Compiles and installs a filter in the daemon handler
 *
 * Inputs:
 *	- pd: the pktd handler descriptor
 *	- filter: a string describing the filter to be installed
 *	- netmask: netmask of the local net
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
static int set_pcap_filter (pcap_t *pd, const char *filter, u_long netmask)
{
	/* compile the filter */
	struct bpf_program code;
	if ( pcap_compile(pd, &code, (char *) filter, 1, netmask) < 0 ) {
		wire_errcode = WIRE_ERR_LOCAL_FILTER;
		return -1;
	}

	/* install it */
	if ( pcap_setfilter(pd, &code) < 0 ) {
		wire_errcode = WIRE_ERR_LOCAL_FILTER;
		return -1;
	}

	return 0;
}



/*
 * open_pcap_file  
 *
 *  Associates a packet capture descriptor to a file
 *  
 * Inputs:
 *	- read_file: a string describing the file which is to be read
 *	- filter: a string describing the filter to be installed
 *
 * Output:
 *	- return: the packet capture descriptor if correct, NULL if there were
 *	problems
 * 
 */
static pcap_t *open_pcap_file (const char *read_file, const char *filter)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;

	if ((pd = pcap_open_offline((char*) read_file, errbuf)) != 0) {
		wire_errcode = WIRE_ERR_LOCAL_NO_SUCH_FILE;
		return NULL;
	}
	if (set_pcap_filter(pd, filter, 0L) != 0) {
		free (pd);
		return NULL;
	}

	return pd;
}



/*
 * open_pktd_daemon
 *
 *  Opens a connection to the pktd packet capture daemon
 *  
 * Inputs:
 *	- pdd: pktd connection description
 *	- filename: pattern of the file where packets will be written (NULL if 
 *	packets will be taken from a port)
 *	- filter: the filter to be installed
 *	- immediate_delivery: whether the daemon must cluster packets before 
 *	  dumping them to disk or the socket
 *	- compression: whether the daemon must compress the packets before 
 *	  dumping them to the socket
 *
 * Output:
 *	- filename: name of the file were packets will be written
 *	- return: the status that the daemon reported (<0 if problems)
 * 
 */
int open_pktd_daemon (pktd_t *pdd, char *filename, const char *filter, 
		int immediate_delivery, int compression)
{
	int timeout;
	u_int port = 0;
	int request, command, status;
	int ctrlfd;
	uid_t uid, gid, pid;
	socklen_t alen;
	struct sockaddr_in sin;
	int cfd;


	timeout = 1000;

	/* open the ctrl connection to the server */
	if ((ctrlfd = pktd_client_socket (PROT_SERVERPORT)) < 0) {
		fprintf (log_file, "YYY: error opening a connection to the daemon\n");
		return -1;
	}

	/* get the process identification tuple (uid, gid, and pid) */
	uid = geteuid();
	gid = getegid();
	pid = getpid();


	if (!ISSET(pdd->mode,W_DW)) {
		/* packets will be received through a port */

		/* open the data connection to the server */
		if ((pdd->datafd = pktd_server_socket (&port)) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error opening the local data socket\n");
			return -1;
		}

		/* send the wire_init message to the server */
		if (pktd_send (ctrlfd, PROT_TYPE_REQUEST, PROT_TYPE_WIRE_INIT_P, 0, 
				uid, gid, pid, filter, pdd->snaplen, port, immediate_delivery, 
				compression, pdd->co.rm_offset, pdd->co.ip_mask, pdd->co.tcp_mask, 
				pdd->co.udp_mask) < 0) {
			close (ctrlfd);
			close (pdd->datafd);
			fprintf (log_file, "YYY: error sending command to the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* get the answer from the server */
		if (pktd_recv (ctrlfd, &request, &command, &status) < 0) {
			close (ctrlfd);
			close (pdd->datafd);
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* close the control socket */
		close (ctrlfd);

		if (status != 0) {
			close (pdd->datafd);
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* wait until you can accept the daemon */
		memset (&sin, 0, sizeof(sin));
		alen = sizeof(sin);
		if ((cfd = accept(pdd->datafd, (struct sockaddr *)&sin, &alen)) < 0) {
			close (pdd->datafd);
			perror ("accept()");
			return -1;
		}
		close (pdd->datafd);
		pdd->datafd = cfd;


	} else {
		/* packets will be dumped to a daemon-located file */

		/* send the wire_init message to the server */
		if (pktd_send (ctrlfd, PROT_TYPE_REQUEST, PROT_TYPE_WIRE_INIT_F, 0, 
				uid, gid, pid, filter, pdd->snaplen, pdd->cp.time, 
				pdd->cp.length, pdd->cp.files, immediate_delivery, compression, 
				pdd->co.rm_offset, pdd->co.ip_mask, pdd->co.tcp_mask, 
				pdd->co.udp_mask, filename) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error sending a command to the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* get the answer from the server */
		if (pktd_recv (ctrlfd, &request, &command, &status) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* close the control socket */
		close (ctrlfd);

		if (status != 0) {
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

	}

	/* copy the information sent by the daemon */
	pdd->cookie = pktd_prot_cookie;
	pdd->datalink = pktd_prot_datalink;
	pdd->hdr_size = pktd_prot_hdr_size;
	pdd->start_stat.ps_recv = pktd_prot_ps_recv;
	pdd->start_stat.ps_drop = pktd_prot_ps_drop;
	pdd->start_stat.ps_ifdrop = pktd_prot_ps_ifdrop;
	if (ISSET(pdd->mode,W_DW)) {
		strcpy (filename, pktd_prot_file_path);
	}

	return 0;
}




/*
 * wire_init
 *
 *  Opens a connection to the pktd daemon in order to install a packet 
 *  filter
 *  
 * Inputs:
 *	- filter: a string describing the filter to be installed
 *	- snaplen: snapshot length; amount of each packet to capture
 *	- mode: type of connection to the pktd daemon. It is set as 
 *	  an OR of several flags, including: 
 *			* W_DW, W_LW: daemon/local writing. The packet stream is 
 *				dumped to a file (at the daemon's host or local) instead of 
 *				a callback being called per packet
 *			* W_ID: immediate delivery (the daemon will forward any packets 
 *				as soon as they are received). The default is buffered delivery, 
 *				where, for performance's sake, packets are clustered before 
 *				being forwarded
 *			* W_CO: compression (the daemon will compress packets). Default 
 *			  is no compression 
 *			* W_KC: keep compressed packets: don't try to uncompress the 
 *				compressed traces. Default is to uncompress the packets. 
 *	- cp: checkpointing information (NULL means no checkpointing)
 *	- co: compression information (NULL means default/no compression)
 *	- read_file: file to be read
 *	- write_file: file pattern where the packets will be written
 *
 * Output:
 *	- return: NULL if problems, else a pktd_t pointer
 *  - errors are reported on wire_errcode
 *
 */
pktd_t *wire_init(const char *filter, int snaplen, int mode, cp_t *cp,  
		co_t *co, const char *read_file, char *write_file) 
{
	pktd_t *pdd;
	struct pcap_stat stat;

	wire_errcode = WIRE_ERR_NONE;

	/* stderr is not a constant expression (glibc-faq 3.9) */
	log_file = stderr;


	/* create the pktd_t structure */
	pdd = malloc (sizeof(*pdd));
	if (pdd == NULL) {
		wire_errcode = WIRE_ERR_LOCAL_OUT_OF_MEMORY;
		return NULL;
	}


	/* initialize the pktd_t structure */
	pdd->wire_errcode = WIRE_ERR_NONE;
	pdd->snaplen = snaplen;
	pdd->datafd = -1;
	pdd->localfp = NULL;
	pdd->offset = 0;
	pdd->cookie = 0;
	pdd->dumper = NULL;
	pdd->mode = mode;
	strcpy(pdd->filter, filter);

	if (ISSET(pdd->mode, W_CO)) {
		pdd->codec = create_codec();
		if (co != NULL) {
			pdd->co.rm_offset = co->rm_offset;
			pdd->co.ip_mask = co->ip_mask;
			pdd->co.tcp_mask = co->tcp_mask;
			pdd->co.udp_mask = co->udp_mask;
		} else {
			pdd->co.rm_offset = DEFAULT_PKTD_COMPRESSION_RESTART_MARKER;
			pdd->co.ip_mask = DEFAULT_PKTD_COMPRESSION_IP_MASK;
			pdd->co.tcp_mask = DEFAULT_PKTD_COMPRESSION_TCP_MASK;
			pdd->co.udp_mask = DEFAULT_PKTD_COMPRESSION_UDP_MASK;
		}
	} else {
		pdd->codec = NULL;
		pdd->co.ip_mask = 0;
		pdd->co.tcp_mask = 0;
		pdd->co.udp_mask = 0;
		pdd->co.rm_offset = 0;
	}


	if (read_file) {
		/* packets will be obtained from a file */
		pdd->reading_offline = 1;
		pdd->pd = open_pcap_file(read_file, filter);
		if (pdd->pd == NULL) {
			wire_errcode = WIRE_ERR_LOCAL_CANT_OPEN_FILE;
			free (pdd);
			return NULL;
		}

		if (write_file) {
			pdd->dumper = pcap_dump_open (pdd->pd, (char *)write_file);
			if (!pdd->dumper) {
				wire_errcode = WIRE_ERR_LOCAL_CANT_OPEN_TRACE_FILE;
				free (pdd);
				return NULL;
			}
		}

		pdd->datalink = pcap_datalink(pdd->pd);
		(void)wire_set_hdr_size(pdd);
		return pdd;
	}


	/* packets will be obtained from a network interface */
	pdd->reading_offline = 0;
	pdd->cp.time = cp->time;
	pdd->cp.length = cp->length;
	pdd->cp.files = cp->files;


	/* check if the write_file pattern is correct */
	if ((write_file != NULL) && (wire_check_pattern (write_file) < 0)) {
		wire_errcode = WIRE_ERR_LOCAL_ILLEGAL_PATTERN;
		free (pdd);
		return NULL;
	}


	/* daemon writing */
	if (ISSET(pdd->mode, W_DW)) {
		/* open a link to the daemon, which will filter its network interface */
		if (open_pktd_daemon (pdd, write_file, filter, ISSET(pdd->mode, W_ID), 
				ISSET(pdd->mode, W_CO)) < 0) {
			free (pdd);
			return NULL;
		}
		return pdd;
	}


	/* local writing */
	if (ISSET(pdd->mode, W_LW)) {
		/* open the local write file */
		if ((pdd->localfp = lfopen ((char *)write_file, 8192)) == NULL) {
			wire_errcode = WIRE_ERR_LOCAL_CANT_OPEN_TRACE_FILE;
			free (pdd);
			return NULL;
		}
	}


	/* open the connection to the daemon */
	if (open_pktd_daemon (pdd, NULL, filter, ISSET(pdd->mode, W_ID), 
			ISSET(pdd->mode, W_CO)) < 0) {
		(void)lfclose (pdd->localfp);
		free (pdd);
		return NULL;
	}


	/* if want to keep packets compressed, set the correct DLT */
	if (ISSET(pdd->mode, W_KC)) {
		pdd->datalink = DLT_COMPRESSED;
	}


	if (ISSET(pdd->mode, W_LW)) {
		/* write the pcap extended header */
		if (pktd_lfwrite_ext_header (pdd->localfp, pdd->snaplen, 
				pdd->datalink, &pdd->co, pdd->filter) < 0) {
			(void)lfclose (pdd->localfp);
			(void)wire_done (pdd, &stat);
			free (pdd);
			return NULL;
		}
	}

	return pdd;
}




/*
 * wire_done
 *
 *	Closes up a packet filter
 *
 * Inputs:
 *	- pdd: pktd connection description
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
int wire_done (pktd_t *pdd, struct pcap_stat *ps)
{
	int request, command, status;
	int ctrlfd;

	if (pdd->dumper) {
		pcap_dump_close (pdd->dumper);
	}

	/* initialize the answers */
	wire_errcode = WIRE_ERR_NONE;

	if (pdd->cookie != 0) {
		/* the network interface is in the daemon */

		/* open the connection to the daemon */
		if ((ctrlfd = pktd_client_socket (PROT_SERVERPORT)) < 0) {
			if (pdd->datafd >= 0) {
				close (pdd->datafd);
			}
			free (pdd);
			return -1;
		}

		/* send a wire_done message to the daemon */
		if (pktd_send (ctrlfd, PROT_TYPE_REQUEST, PROT_TYPE_WIRE_DONE, 0, 
				pdd->cookie) < 0) {
			close (ctrlfd);
			if (pdd->datafd >= 0) {
				close (pdd->datafd);
			}
			free (pdd);
			return -1;
		}

		/* get the answer from the server */
		if (pktd_recv (ctrlfd, &request, &command, &status) < 0) {
			close (ctrlfd);
			if (pdd->datafd >= 0) {
				close (pdd->datafd);
			}
			free (pdd);
			return -1;
		}

		ps->ps_recv = pktd_prot_ps_recv - pdd->start_stat.ps_recv;
		ps->ps_drop = pktd_prot_ps_drop - pdd->start_stat.ps_drop;
		ps->ps_ifdrop = pktd_prot_ps_ifdrop - pdd->start_stat.ps_ifdrop;

		/* close the control and data sockets */
		close (ctrlfd);
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
		}

		free (pdd);
		return status;
	}

	/* close the local write file if necessary */
	if (pdd->localfp != NULL) {
		(void)lfclose (pdd->localfp);
		pdd->localfp = NULL;
	}
	if (pdd->pd != NULL) {
		pcap_close (pdd->pd);
	}
	free (pdd);
	return 0;
}




/*
 * wire_stats
 *
 *	Gets packet statistics since opening
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
int wire_stats (pktd_t *pdd, struct pcap_stat *ps)
{
	int request, command, status;
	int ctrlfd;

	/* initialize the answers */
	wire_errcode = WIRE_ERR_NONE;

	if (pdd->cookie != 0) {
		/* open the ctrl connection to the server */
		if ((ctrlfd = pktd_client_socket (PROT_SERVERPORT)) < 0) {
			fprintf (log_file, "YYY: error opening a connection to the daemon\n");
			return -1;
		}

		/* send a wire_stats message to the daemon */
		if (pktd_send (ctrlfd, PROT_TYPE_REQUEST, PROT_TYPE_WIRE_STATS, 0, 
				pdd->cookie) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error sending command to the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* get the answer from the server */
		if (pktd_recv (ctrlfd, &request, &command, &status) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* close the control socket */
		close (ctrlfd);

		ps->ps_recv = pktd_prot_ps_recv - pdd->start_stat.ps_recv;
		ps->ps_drop = pktd_prot_ps_drop - pdd->start_stat.ps_drop;
		ps->ps_ifdrop = pktd_prot_ps_ifdrop - pdd->start_stat.ps_ifdrop;

		return status;
	}


	/* can't get the packet summary if reading from a savefile. */
	if ((pdd->pd != NULL) && !pcap_file(pdd->pd)) {
		struct pcap_stat stat;
		if (pcap_stats (pdd->pd, &stat) < 0) {
			wire_errcode = WIRE_ERR_LOCAL_PCAP;
			return -1;
		}
		*ps = stat;
	}

	return 0;
}




/*
 * wire_flush
 *
 *	Requests the daemon to flush the client buffer
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
int wire_flush (pktd_t *pdd)
{
	int request, command, status;
	int ctrlfd;

	/* initialize the answers */
	wire_errcode = WIRE_ERR_NONE;

	if (pdd->cookie != 0) {
		/* open the ctrl connection to the server */
		if ((ctrlfd = pktd_client_socket (PROT_SERVERPORT)) < 0) {
			fprintf (log_file, "YYY: error opening a connection to the daemon\n");
			return -1;
		}

		/* send a wire_stats message to the daemon */
		if (pktd_send (ctrlfd, PROT_TYPE_REQUEST, PROT_TYPE_WIRE_FLUSH, 0, 
				pdd->cookie) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error sending command to the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* get the answer from the server */
		if (pktd_recv (ctrlfd, &request, &command, &status) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* close the control socket */
		close (ctrlfd);

		return status;
	}

	return 0;
}




/*
 * wire_setfilter
 *
 *	Installs a packet filter
 * 
 * Inputs:
 *	- pdd: pktd connection description
 *	- filter: a string describing the filter to be installed
 *	- cp: checkpointing information (NULL means no checkpointing)
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
int wire_setfilter (pktd_t *pdd, const char *filter, cp_t *cp)  
{
	int request, command, status;
	int ctrlfd;

	/* write up the new data */
	sprintf (pdd->filter, filter);
	pdd->cp.time = cp->time;
	pdd->cp.length = cp->length;
	pdd->cp.files = cp->files;

	if (pdd->cookie != 0) {
		/* open the ctrl connection to the server */
		if ((ctrlfd = pktd_client_socket (PROT_SERVERPORT)) < 0) {
			fprintf (log_file, "YYY: error opening a connection to the daemon\n");
			return -1;
		}

		/* send the wire_setfilter message to the server */
		if (pktd_send (ctrlfd, PROT_TYPE_REQUEST, PROT_TYPE_WIRE_SETFILTER, 0, 
				pdd->cookie, filter, pdd->snaplen, pdd->cp.time, pdd->cp.length, 
				pdd->cp.files) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error sending command to the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* get the answer from the server */
		if (pktd_recv (ctrlfd, &request, &command, &status) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* close the control socket */
		close (ctrlfd);

		return status;
	}

	return set_pcap_filter (pdd->pd, filter, 0L);
}



/*
 * wire_checkpoint
 *
 *	Forces the daemon to checkpoint the client's file
 * 
 *
 * Inputs:
 *	- pdd: the pktd connection descriptor
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
int wire_checkpoint (pktd_t *pdd)
{
	return wire_setfilter (pdd, pdd->filter, NULL);
}



/*
 * wire_inject
 *
 *	Requests a packet injection to the daemon
 * 
 * Inputs:
 *	- pdd: the pktd connection descriptor
 *	- ip: the packets (beginning with the IP header)
 *
 * Output:
 *	- return: 0 if correct, !=0 if there were problems
 *
 */
int wire_inject (pktd_t *pdd, u_char *ip)
{
	int request, command, status;
	int ctrlfd;

	if (pdd->cookie != 0) {
		/* open the ctrl connection to the server */
		if ((ctrlfd = pktd_client_socket (PROT_SERVERPORT)) < 0) {
			fprintf (log_file, "YYY: error opening a connection to the daemon\n");
			return -1;
		}

		/* send the wire_inject message to the server */
		if (pktd_send (ctrlfd, PROT_TYPE_REQUEST, PROT_TYPE_WIRE_INJECT, 0, 
				pdd->cookie, ip) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error sending command to the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* get the answer from the server */
		if (pktd_recv (ctrlfd, &request, &command, &status) < 0) {
			close (ctrlfd);
			fprintf (log_file, "YYY: error received from the daemon (%s)\n", 
					wire_err_msg(pdd->wire_errcode));
			return -1;
		}

		/* close the control socket */
		close (ctrlfd);

		return status;
	}

	return -1;
}



/*
 * wire_max_fd
 */
int wire_max_fd (pktd_t *pdd)
{
	if (pdd->cookie != 0) {
		return pdd->datafd;
	}

	return (pdd->pd != NULL) ? pcap_fileno(pdd->pd) : -1;
}




/*
 * wire_add_fds
 */
int wire_add_fds (pktd_t *pdd, fd_set *fds)
{
	if (pdd->datafd < 0) {
		pdd->wire_errcode = WIRE_ERR_LOCAL_NO_PKTD_SOCKET;
		return -1;
	}

	if (pdd->cookie != 0) {
/* fprintf (log_file, "wire: wire_add_fds: adding descriptor %i to fds\n", datafd); */
		FD_SET(pdd->datafd, fds);
		return 0;
	}
	if (pdd->pd == NULL) {
		pdd->wire_errcode = WIRE_ERR_LOCAL_PCAP;
		return -1;
	}

	FD_SET(pcap_fileno(pdd->pd), fds);
	return 0;
}




/*
 * wire_is_set
 */
int wire_is_set (pktd_t *pdd, fd_set *fds)
{
	if (pdd->datafd < 0) {
		pdd->wire_errcode = WIRE_ERR_LOCAL_NO_PKTD_SOCKET;
		return -1;
	}

	if (pdd->cookie != 0) {
/* fprintf (log_file, "wire: wire_is_set: checking descriptor %i to fds\n", datafd); */
		return FD_ISSET(pdd->datafd, fds);
	}
	if (pdd->pd == NULL) {
		pdd->wire_errcode = WIRE_ERR_LOCAL_PCAP;
		return -1;
	}

	return FD_ISSET(pcap_fileno(pdd->pd), fds);
}




/*
 * wire_num_filter_drops
 */
int wire_num_filter_drops (pktd_t *pdd)
{
	struct pcap_stat stat;

	if (wire_stats (pdd, &stat) < 0) {
		return -1;
	}

	return stat.ps_drop;
}



struct wire_info {
	void *user_data;
	wire_callback callback;
	pktd_t *pdd;
};

/*
 * library_callback
 *
 *	This is the main callback called by the libwire library.
 * 
 * Inputs:
 *	- user: a user-defined string
 *	- hdr: the packet header
 *	- pkt: the just-arrived packet
 *
 */
static void library_callback(u_char *user, const struct pcap_pkthdr *hdr, 
		const u_char *pkt)
{
	struct wire_info *wi;
	int save_bytes;

	wi = (struct wire_info *) user;

	save_bytes = wi->callback(pkt, hdr->ts, hdr->len, hdr->caplen, 
			wi->user_data);
	if (save_bytes && wi->pdd->dumper) {
		struct pcap_pkthdr mod_hdr;
		mod_hdr = *hdr;
		if ((save_bytes + wi->pdd->hdr_size) < mod_hdr.caplen) {
			mod_hdr.caplen = save_bytes + wi->pdd->hdr_size;
		}
		pcap_dump((u_char *) wi->pdd->dumper, &mod_hdr, pkt);
	}
}




/*
 * read_up_to
 *
 *	Reads up to size bytes from the descriptor fd. The buffers is assumed 
 *	to have *offset valid bytes beforehand 
 *
 * Inputs:
 *	- fd: descriptor
 *	- buffer: data buffer
 *	- offset: number of currently valid bytes
 *	- size: number of bytes requested
 *
 * Output:
 *	- return: number of valid bytes after lecture (<0 if eof or error)
 *
 */
int read_up_to (int fd, u_char* buffer, int offset, int size)
{
	int result = 0;
	int nbytes = offset;


	if (nbytes < size) {
again:
		result = read (fd, buffer+nbytes, size-nbytes);
		if (result < 0) {
			if (errno == EINTR) {
				goto again;
			}

			perror ("read()");
			return WIRE_READ_ERROR;

		} else if (result == 0) {
			/* eof in the datafd */
			return WIRE_READ_EOF;

		} else {
			nbytes += result;
		}
	}

	return nbytes;
}




/*
 * wire_activity
 *
 *	Checks if the packet filter daemon reported any activity
 *
 * Inputs:
 *	- pdd: the pktd connection descriptor
 *	- fds: a set of file descriptors
 *	- cb: the callback to be triggered on activity
 *	- user_data: a user-defined string
 *
 * Output:
 *	- return: number of packets read (-1 if eof, -2 if error)
 *
 */
int wire_activity (pktd_t *pdd, fd_set *fds, wire_callback cb, 
		void *user_data)
{
	struct wire_info wi;
	struct pcap_pkthdr pkthdr;
	int result;


	wi.user_data = user_data;
	wi.callback = cb;
	wi.pdd = pdd;

	if (pdd->reading_offline) {
		return pcap_dispatch (pdd->pd, 0, library_callback, (u_char *) &wi);
	}

	if (pdd->cookie != 0) {

		if (ISSET(pdd->mode, W_CO)) {
			if (ISSET(pdd->mode, W_KC)) {
				result = wire_read_compressed_buffer (pdd, &pkthdr);
			} else {
				result = wire_read_and_uncompress_packet (pdd, &pkthdr);
			}
		} else {
			result = wire_read_raw_packet (pdd, &pkthdr);
		}

		if ((result == WIRE_READ_ERROR) ||
				(result == WIRE_READ_EOF) ||
				(result == WIRE_READ_INCOMPLETE) ||
				(result == 0)) {
			return result;
		}

		/* local writing */
		if (ISSET(pdd->mode, W_LW)) {
			if (ISSET(pdd->mode, W_KC)) {
				/* write the full buffer now */
				if (lfwrite (pdd->localfp, pdd->buffer, pdd->offset) < 0) {
					(void)lfclose (pdd->localfp);
					pdd->localfp = NULL;
				}
			} else {
				/* write the packet header and contents now */
				if (lfwrite (pdd->localfp, pdd->buffer, TCPDUMP_PACKET_HEADER_LENGTH + 
						pkthdr.caplen) < 0) {
					(void)lfclose (pdd->localfp);
					pdd->localfp = NULL;
				}
			}
		}

		/* call the user callback for this packet */
		if (ISSET(pdd->mode, W_KC)) {
			library_callback ((u_char *) &wi, &pkthdr, pdd->buffer);
		} else {
			library_callback ((u_char *) &wi, &pkthdr, pdd->buffer + 
					TCPDUMP_PACKET_HEADER_LENGTH);
		}

		/* reset the buffer offset */
		pdd->offset = 0;

	  return 1;
	}

	if (FD_ISSET(pcap_fileno(pdd->pd), fds)) {
		return pcap_dispatch(pdd->pd, -1, library_callback, (u_char *) &wi);
	} else {
		return 0;
	}
}




/*
 * wire_read_raw_packet
 *
 *	Read a raw packet
 *
 * Inputs:
 *	- pdd: the pktd connection descriptor
 *
 * Output:
 *	- pkthdr: the packet header
 *	- return: number of packets read (<0 means incomplete, eof or error)
 *
 */
int wire_read_raw_packet (pktd_t *pdd, struct pcap_pkthdr *pkthdr)
{
	int length;

	/* read the data header */
	pdd->offset = read_up_to (pdd->datafd, pdd->buffer, pdd->offset, 
			TCPDUMP_PACKET_HEADER_LENGTH);
	if (pdd->offset == WIRE_READ_ERROR) {
		/* read error: close the data socket and terminate */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		return WIRE_READ_ERROR;

	} else if (pdd->offset == WIRE_READ_EOF) {
		/* eof: close the data socket */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		pdd->cookie = 0;
		return WIRE_READ_EOF;

	} else if (pdd->offset < TCPDUMP_PACKET_HEADER_LENGTH) {
		/* part of the packet is still buffered at the daemon: return */
		return WIRE_READ_INCOMPLETE;
	}

	/* interpret the header */
	length = 0;
	pkthdr->ts.tv_sec = ntohl (*(long *)(pdd->buffer+length));
	length += 4;
	pkthdr->ts.tv_usec = ntohl (*(long *)(pdd->buffer+length));
	length += 4;
	pkthdr->caplen = ntohl (*(long *)(pdd->buffer+length));
	length += 4;
	pkthdr->len = ntohl (*(long *)(pdd->buffer+length));
	length += 4;


	/* get the rest of the packet */
	pdd->offset = read_up_to (pdd->datafd, pdd->buffer, pdd->offset, 
			TCPDUMP_PACKET_HEADER_LENGTH + pkthdr->caplen);
	if (pdd->offset == WIRE_READ_ERROR) {
		/* read error: close the data socket and terminate */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		return WIRE_READ_ERROR;

	} else if (pdd->offset == WIRE_READ_EOF) {
		/* eof: close the data socket */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		pdd->cookie = 0;
		return WIRE_READ_EOF;

	} else if (pdd->offset < (TCPDUMP_PACKET_HEADER_LENGTH + pkthdr->caplen)) {
		/* part of the packet is still buffered at the daemon: return */
		return WIRE_READ_INCOMPLETE;
	}

	return 1;
}




/*
 * wire_read_and_uncompress_packet
 *
 *	Read a compressed packet and uncompress it
 *
 * Inputs:
 *	- pdd: the pktd connection descriptor
 *
 * Output:
 *	- pkthdr: the packet header
 *	- return: number of packets read (<0 means incomplete, eof, or error)
 *
 */
int wire_read_and_uncompress_packet (pktd_t *pdd, struct pcap_pkthdr *pkthdr)
{
	int i;
	static u_char compressed_buffer[MAX_COMPRESSED_LENGTH];
	static int offset = 0;

	/* read the trace length */
	offset = read_up_to (pdd->datafd, compressed_buffer, offset, 
			TCPDUMP_PACKET_HEADER_LENGTH_COMPRESSED);
	if (offset == WIRE_READ_ERROR) {
		/* read error: close the data socket and terminate */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		return WIRE_READ_ERROR;

	} else if (offset == WIRE_READ_EOF) {
		/* eof: close the data socket */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		pdd->cookie = 0;
		return WIRE_READ_EOF;

	} else if (offset == COMPRESSION_INIT_CODEC) {
		/* codec initialization requested */
		init_codec (pdd->codec);
		return 0;

	} else if (offset < TCPDUMP_PACKET_HEADER_LENGTH_COMPRESSED) {
		/* part of the packet is still buffered at the daemon: return */
		return WIRE_READ_INCOMPLETE;
	}

	i = (u_int8_t)(compressed_buffer[0]);

	/* check if the trace is a padding */
	if (i == COMPRESSION_PADDING) {
		offset = 0;
		return 0;
	}


	/* get the rest of the compressed packet */
	offset = read_up_to (pdd->datafd, compressed_buffer, offset, i);
	if (offset == WIRE_READ_ERROR) {
		/* read error: close the data socket and terminate */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		return WIRE_READ_ERROR;

	} else if (offset == WIRE_READ_EOF) {
		/* eof: close the data socket */
		if (pdd->datafd >= 0) {
			close (pdd->datafd);
			pdd->datafd = -1;
		}
		pdd->cookie = 0;
		return WIRE_READ_EOF;

	} else if (offset < i) {
		/* part of the packet is still buffered at the daemon: return */
		return WIRE_READ_INCOMPLETE;
	}


	/* decode the packet */
	decode_trace (pdd->codec, compressed_buffer, pkthdr, pdd->buffer);

	offset = 0;

	return 1;
}




/*
 * wire_read_compressed_buffer
 *
 *	Read a buffer of compressed packets
 *
 * Inputs:
 *	- pdd: pktd connection descriptor
 *
 * Output:
 *	- pdd->buffer: buffer with compressed packets
 *	- pdd->offset: amount of data read
 *	- pkthdr->len: amount of data read
 *	- return: amount of data read (-1 if eof, -2 if error)
 *
 */
int wire_read_compressed_buffer (pktd_t *pdd, struct pcap_pkthdr *pkthdr)
{

	/* read the buffer */
	pdd->offset = read (pdd->datafd, pdd->buffer, MAXDATABUFFER);
	pkthdr->len = pdd->offset;
	return pdd->offset;
}




/*
 * wire_check_pattern
 *
 *	Checks if a filename pattern is allowed before requesting installation 
 *	to the daemon
 *
 * Inputs:
 *	- pattern: the filename pattern
 *
 * Output:
 *	- return: 0 if it is ok, !=0 otherwise
 *
 */
int wire_check_pattern (const char *pattern)
{
	/* XXX: should check here:
	 * XXX		- no backslashes
	 * XXX		- only one %d as non [a-zA-Z0-9-_] char
	 */
	return 0;
}


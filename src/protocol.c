/*
 * protocol.c --
 *
 *	PKTD multiplexer daemon: client-server protocol. This file includes 
 *	all the functions common to clients and daemon.
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
#include <stdlib.h>
#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "protocol.h"



/* variables used by pktd_recv to pass request arguments up */
u_int32_t pktd_prot_cookie;
char pktd_prot_filter[PROT_MAX_INDIVIDUAL_FILTER];
char pktd_prot_file_path[PROT_MAXFILENAME];
char pktd_prot_file_pattern[PROT_MAXFILENAME];
u_int pktd_prot_port;
int pktd_prot_immediate_delivery;
int pktd_prot_compression;
u_int pktd_prot_snaplen;
u_int16_t pktd_prot_cp_time;
u_int16_t pktd_prot_cp_length;
u_int16_t pktd_prot_cp_files;
u_int8_t pktd_prot_co_ip_mask;
u_int16_t pktd_prot_co_tcp_mask;
u_int8_t pktd_prot_co_udp_mask;
u_int32_t pktd_prot_co_rm_offset;
u_int32_t pktd_prot_ps_recv;
u_int32_t pktd_prot_ps_drop;
u_int32_t pktd_prot_ps_ifdrop;
u_int32_t pktd_prot_uid, pktd_prot_gid, pktd_prot_pid;
u_int32_t pktd_prot_datalink;
int pktd_prot_hdr_size;
char pktd_prot_ip[PROT_MAX_IP_LENGTH];


/* common error code variable definition */
int wire_errcode;



/*
 * wire_err_msg
 *
 *	Maps errors to strings describing such errors
 *
 * Output:
 *	- return: a string describing the error stored in wire_errcode
 *
 */
const char *wire_err_msg ()
{
	switch (wire_errcode) {
		case WIRE_ERR_NONE:
			return "no errors";

		/* pcap errors */
		case WIRE_ERR_LOCAL_OTHER:
		case WIRE_ERR_PKTD_OTHER:
			return "other error";

		case WIRE_ERR_LOCAL_OUT_OF_MEMORY:
		case WIRE_ERR_PKTD_OUT_OF_MEMORY:
			return "out of memory";

		case WIRE_ERR_LOCAL_NO_SUCH_FILE:
		case WIRE_ERR_PKTD_NO_SUCH_FILE:
			return "no such file";

		case WIRE_ERR_LOCAL_FILTER:
		case WIRE_ERR_PKTD_FILTER:
			return "incorrect filter";

		case WIRE_ERR_LOCAL_INTERNAL:
		case WIRE_ERR_PKTD_INTERNAL:
			return "internal error";

		case WIRE_ERR_LOCAL_UNKNOWN_LINK_TYPE:
		case WIRE_ERR_PKTD_UNKNOWN_LINK_TYPE:
			return "unknown link type";

		case WIRE_ERR_LOCAL_EXCESSIVE_FILTER:
		case WIRE_ERR_PKTD_EXCESSIVE_FILTER:
			return "filter too long";

		case WIRE_ERR_LOCAL_PCAP:
		case WIRE_ERR_PKTD_PCAP:
			return "pcap initialization failed";

		case WIRE_ERR_LOCAL_CANT_OPEN_FILE:
		case WIRE_ERR_PKTD_CANT_OPEN_FILE:
			return "can't open file to read from";

		case WIRE_ERR_LOCAL_CANT_OPEN_TRACE_FILE:
		case WIRE_ERR_PKTD_CANT_OPEN_TRACE_FILE:
			return "can't open file to write to";

		case WIRE_ERR_LOCAL_CANT_OPEN_FILTER:
		case WIRE_ERR_PKTD_CANT_OPEN_FILTER:
			return "can't open packet filter";

		case WIRE_ERR_LOCAL_CANT_OPEN_FILTER_NO_PERMISSION:
		case WIRE_ERR_PKTD_CANT_OPEN_FILTER_NO_PERMISSION:
			return "can't open packet filter (no permission)";

		case WIRE_ERR_LOCAL_ILLEGAL_PATTERN:
		case WIRE_ERR_PKTD_ILLEGAL_PATTERN:
			return "illegal file pattern";

		case WIRE_ERR_LOCAL_IMMEDIATE_MODE:
		case WIRE_ERR_PKTD_IMMEDIATE_MODE:
			return "can't set immediate mode";

		case WIRE_ERR_LOCAL_NO_PKTD_SOCKET:
			return "not connected to the daemon";


		/* protocol errors */
		case WIRE_ERR_PROT_UNRECOGNIZED_COMMAND:
			return "command unrecognized";

		case WIRE_ERR_PROT_BAD_FORMED_REQUEST:
			return "bad-formed request";

		case WIRE_ERR_PROT_MISBEHAVING_CLIENT:
			return "the client is misbehaving";

		case WIRE_ERR_PROT_SOCKET:
			return "cannot create socket (socket call)";

		case WIRE_ERR_PROT_SETSOCKOPT:
			return "cannot set socket options (setsockopt call)";

		case WIRE_ERR_PROT_BIND:
			return "cannot bind socket (bind call)";

		case WIRE_ERR_PROT_GETSOCKNAME:
			return "cannot get socket name (getsockname call)";

		case WIRE_ERR_PROT_LISTEN:
			return "cannot put socket in passive mode (listen call)";

		case WIRE_ERR_PROT_CONNECT:
			return "cannot connect socket in active mode (connect call)";

		case WIRE_ERR_PROT_SENDING_COMMAND:
			return "error while trying to send a command to the daemon";

		case WIRE_ERR_PROT_SENDING_DATA:
			return "error while trying to send data";

		case WIRE_ERR_PROT_CANNOT_WRITE_FILE:
			return "the daemon couldn't write into the client file";

		case WIRE_ERR_PROT_ILLEGAL_PATTERN:
			return "the file pattern is illegal";

		case WIRE_ERR_PROT_INTERNAL_PROBLEMS:
			return "the server reported internal problems";


		/* daemon-specific errors */
		case WIRE_ERR_PKTD_TOO_MANY_CLIENTS:
			return "the daemon is dealing with too many clients";

		case WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_FILTER:
			return "the client has no permission to run that filter";

		case WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_WRITE:
			return "the client has no permission to write that packet";

		case WIRE_ERR_PKTD_WRITE_DISABLED:
			return "packet injection is disabled in the daemon";

		case WIRE_ERR_PKTD_NO_WRITE_DEVICE_ACCESS:
			return "the daemon cannot access the injection device";

		case WIRE_ERR_PKTD_INJECTION_OPEN:
			return "daemon couldn't open injection device";

		case WIRE_ERR_PKTD_INJECTION_WRITE_IP:
			return "daemon couldn't write on injectio device";

		case WIRE_ERR_PKTD_INJECTION_CLOSE:
			return "daemon couldn't close injection device";

		case WIRE_ERR_PKTD_BAD_COOKIE:
			return "the cookie sent by the client is incorrect";

		case WIRE_ERR_PKTD_NO_DEVICE:
			return "the daemon has no valid device open";

		default:
			return "unknown";
	}
}




/* 
 * pktd_send
 *
 *	Sends a packet to the other side
 *
 * Inputs:
 *	- fd: a socket descriptor
 *	- request: 1 if this is a request, 0 if it is an answer
 *	- command: command requested or answered to
 *	- status: status of the request
 *	- ...: arguments of the request or the answer
 *
 * Output:
 *	- return: 0 if ok, <0 if there was any problem
 *
 */
#if __STDC__
int pktd_send (int fd, int request, int command, int status, ...)
#else
int pktd_send (fd, request, command, status, va_alist)
	int fd;
	int request;
	int command;
	int status;
	va_dcl
#endif
{
	va_list ap;
	char buffer[PROT_MAXLENGTH];
	int length;
	u_int16_t cp_time, cp_length, cp_files;
	u_int32_t co_rm_offset;
	u_int8_t co_ip_mask, co_udp_mask;
	u_int16_t co_tcp_mask;
	char *filter;
	char *filename, *pattern;
	int port;
	int immediate_delivery;
	int compression;
	int snaplen;
	u_int32_t cookie;
	u_int32_t uid, gid, pid;
	u_char* ip;
	u_int32_t ps_recv;
	u_int32_t ps_drop;
	u_int32_t ps_ifdrop;
	u_int32_t datalink;
	int hdr_size;

#if __STDC__
	va_start(ap, status);
#else
	va_start(ap);
#endif

	/* create the packet header */
	buffer[0] = (0xf0 & PROT_VERSION) | (0x08 & ((u_int8_t)request << 3)) | 
			(0x07 & (u_int8_t)command);
	buffer[1] = (u_int8_t)status;
	length = PROT_MINHEADER;

	if (status == WIRE_ERR_NONE) {
		if (request) {
			switch (command) {
				case PROT_TYPE_WIRE_INIT_P:
					/* the client requests receiving packets in a given port
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_INIT_P, 0, uid, gid, pid, filter, snaplen, 
					 * 		port, immediate_delivery, compression, rm_offset,
					 * 		ip_mask, tcp_mask, udp_mask);
					 */
					uid = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(uid);
					length += 4;
					gid = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(gid);
					length += 4;
					pid = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(pid);
					length += 4;
					filter = va_arg (ap, char *);
					strcpy (buffer+length, filter);
					length += (int)strlen(filter) + 1;
					snaplen = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(snaplen);
					length += 2;
					port = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(port);
					length += 2;
					immediate_delivery = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(immediate_delivery);
					length += 2;
					compression = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(compression);
					length += 2;
					co_rm_offset = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(co_rm_offset);
					length += 4;
					co_ip_mask = (u_int8_t)va_arg (ap, int);
					*(u_int8_t *)(buffer+length) = co_ip_mask;
					length += 1;
					co_tcp_mask = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(co_tcp_mask);
					length += 2;
					co_udp_mask = (u_int8_t)va_arg (ap, int);
					*(u_int8_t *)(buffer+length) = co_udp_mask;
					length += 1;
					break;

				case PROT_TYPE_WIRE_INIT_F:
					/* the client requests getting packets in a given file
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_INIT_F, 0, uid, gid, pid, filter, snaplen, 
					 * 		cp_time, cp_length, cp_files, immediate_delivery, 
					 *    compression, rm_offset, ip_mask, tcp_mask, udp_mask, pattern);
					 */
					uid = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(uid);
					length += 4;
					gid = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(gid);
					length += 4;
					pid = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(pid);
					length += 4;
					filter = va_arg (ap, char *);
					strcpy (buffer+length, filter);
					length += (int)strlen(filter) + 1;
					snaplen = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(snaplen);
					length += 2;
					cp_time = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(cp_time);
					length += 2;
					cp_length = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(cp_length);
					length += 2;
					cp_files = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(cp_files);
					length += 2;
					immediate_delivery = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(immediate_delivery);
					length += 2;
					compression = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(compression);
					length += 2;
					co_rm_offset = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(co_rm_offset);
					length += 4;
					co_ip_mask = (u_int8_t)va_arg (ap, int);
					*(u_int8_t *)(buffer+length) = co_ip_mask;
					length += 1;
					co_tcp_mask = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(co_tcp_mask);
					length += 2;
					co_udp_mask = (u_int8_t)va_arg (ap, int);
					*(u_int8_t *)(buffer+length) = co_udp_mask;
					length += 1;
					pattern = va_arg (ap, char *);
					strcpy (buffer+length, pattern);
					length += (int)strlen(pattern) + 1;
					break;

				case PROT_TYPE_WIRE_SETFILTER:
					/* the client requests a change in his filter and/or snaplen
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_SETFILTER, 0, cookie, filter, snaplen, 
					 *		cp_time, cp_length, cp_files);
					 */
					cookie = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl((u_int32_t)cookie);
					length += sizeof(u_int32_t);
					filter = va_arg (ap, char *);
					strcpy (buffer+length, filter);
					length += (int)strlen(filter) + 1;
					snaplen = va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(snaplen);
					length += 2;
					cp_time = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(cp_time);
					length += 2;
					cp_length = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(cp_length);
					length += 2;
					cp_files = (u_int16_t)va_arg (ap, int);
					*(u_int16_t *)(buffer+length) = htons(cp_files);
					length += 2;
					break;

				case PROT_TYPE_WIRE_DONE:
					/* the client requests to close its subfilter
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_DONE, 0, cookie);
					 */
					cookie = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl((u_int32_t)cookie);
					length += sizeof(u_int32_t);
 		    	break;

				case PROT_TYPE_WIRE_STATS:
					/* the client requests to know the device packet statistics
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_STATS, 0, cookie);
					 */
					cookie = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl((u_int32_t)cookie);
					length += sizeof(u_int32_t);
 		    	break;

				case PROT_TYPE_WIRE_FLUSH:
					/* the client requests its buffer to be flushed
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_FLUSH, 0, cookie);
					 */
					cookie = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl((u_int32_t)cookie);
					length += sizeof(u_int32_t);
 		    	break;

				case PROT_TYPE_WIRE_INJECT:
					/* the client requests to send a packet
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_INJECT, 0, cookie, packet);
					 */
					cookie = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl((u_int32_t)cookie);
					length += sizeof(u_int32_t);
					ip = va_arg (ap, u_char*);
					(void)memcpy ((void*)(buffer+length), ip, ntohs(*(u_int16_t*)(ip+2)));
					length += ntohs(*(u_int16_t*)(ip+2));
 		    	break;

				default:
					/* unrecognized command */
					wire_errcode = WIRE_ERR_PROT_UNRECOGNIZED_COMMAND;
					return -1;
					break;
			} /* switch (command) */

		} else { /* request == 0 (i.e., answer) */
			switch (command) {
				case PROT_TYPE_WIRE_INIT_P:
					/* the server is returning the status of the command, the cookie 
					 * and the hdr_size
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_ANSWER, PROT_TYPE_XX, 
					 * 		status, cookie, datalink, hdr_size, 
					 * 		ps_recv, ps_drop, ps_ifdrop);
					 */
					cookie = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl((u_int32_t)cookie);
					length += sizeof(u_int32_t);
					datalink = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(datalink);
					length += sizeof(u_int32_t);
					hdr_size = va_arg (ap, int);
					*(int *)(buffer+length) = htonl(hdr_size);
					length += sizeof(int);
					ps_recv = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_recv);
					length += sizeof(u_int32_t);
					ps_drop = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_drop);
					length += sizeof(u_int32_t);
					ps_ifdrop = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_ifdrop);
					length += sizeof(u_int32_t);
 		    	break;

				case PROT_TYPE_WIRE_INIT_F:
					/* the server is returning the status of the command, the cookie,
					 * and the first file name (including the full path)
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_ANSWER, PROT_TYPE_XX, 
					 * 		status, cookie, filename);
					 */
					cookie = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl((u_int32_t)cookie);
					length += sizeof(u_int32_t);
					filename = va_arg (ap, char *);
					strcpy (buffer+length, filename);
					length += (int)strlen(filename) + 1;
 		    	break;

				case PROT_TYPE_WIRE_SETFILTER:
					/* the server is returning the status of a command
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_ANSWER, PROT_TYPE_XX, 
					 * 		status);
					 */
 		    	break;

				case PROT_TYPE_WIRE_DONE:
					/* the server is returning the status of a wire_done
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_DONE, status, ps_recv, ps_drop, ps_ifdrop);
					 */
					ps_recv = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_recv);
					length += sizeof(u_int32_t);
					ps_drop = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_drop);
					length += sizeof(u_int32_t);
					ps_ifdrop = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_ifdrop);
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_STATS:
					/* the server is returning the device packet statistics
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_STATS, status, ps_recv, ps_drop, ps_ifdrop);
					 */
					ps_recv = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_recv);
					length += sizeof(u_int32_t);
					ps_drop = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_drop);
					length += sizeof(u_int32_t);
					ps_ifdrop = va_arg (ap, u_int32_t);
					*(u_int32_t *)(buffer+length) = htonl(ps_ifdrop);
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_FLUSH:
					/* the server is acknowledging a buffer flush
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_FLUSH, status);
					 */
					break;

				case PROT_TYPE_WIRE_INJECT:
					/* the server is returning the status of a wire_inject
					 *
					 * success = pktd_send (ctrlfd, PROT_TYPE_REQUEST, 
					 * 		PROT_TYPE_WIRE_INJECT, status);
					 */
 		    	break;

				default:
					/* unrecognized command */
					wire_errcode = WIRE_ERR_PROT_UNRECOGNIZED_COMMAND;
					return -1;
					break;
			} /* switch (command) */
		} /* request != 0 (request) || request == 0 (answer)  */
	} /* status == WIRE_ERR_NONE */

	/* close the variable arguments */
	va_end(ap);

	/* write the correct length */
	*(u_int16_t *)(buffer+2) = ntohs(length);

	/* send the message */
	if (write (fd, buffer, length) < 0) {
		/* error while writing the message: the socket is dead */
		wire_errcode = WIRE_ERR_PROT_SENDING_DATA;
		return -1;
	}

	return 0;
}



/* 
 * pktd_recv
 *
 *	Receives a packet from the other side
 *
 * Inputs:
 *	- fd: a socket descriptor
 *
 * Output:
 *	- return: 0 if ok, <0 if there was any problem
 *	- request: 1 if this was a request, 0 if it was an answer
 *	- command: command requested or answered to
 *	- status: status of the request
 *
 */
int pktd_recv (int fd, int *request, int *command, int *status)
{
	char buffer[PROT_MAXLENGTH];
	int length;
	int nbytes, i;
	char *bufp;

	/* to use it: 
	 *
	 * success = pktd_recv (ctrlfd, &request, &command, &status);
	 */

	/* get the minimum header */
again:
	if ((nbytes = read (fd, buffer, PROT_MAXLENGTH)) < PROT_MINHEADER) {
		if (errno == EINTR) {
			goto again;
		}
		wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
		return -1;
  }

	/* check the header */
	if (((u_int8_t)buffer[0] & 0xf0) != PROT_VERSION) {
		wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
		return -1;
	}

	/* get the header information */
	*request = (int) (((u_int8_t)buffer[0] & 0x08) >> 3);
	*command = (int) ((u_int8_t)buffer[0] & 0x07);
	*status = (int) (u_int8_t)buffer[1];
	wire_errcode = *status;
	length = (int) ntohs(*(u_int16_t *)(buffer+2));

	/* read the rest of the message */
	while (nbytes < length) {
		i = read (fd, buffer+nbytes, PROT_MAXLENGTH);
		if (i < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
				return -1;
			}
		} else if (i == 0) {
			break;
		} else {
			nbytes += i;
		}
	}

	length = PROT_MINHEADER;

	/* interpret the rest of the arguments */
	if (*status == WIRE_ERR_NONE) {
		if (*request) {
			switch (*command) {
				case PROT_TYPE_WIRE_INIT_P:
					/* the client has requested receiving packets in a given port */
					pktd_prot_uid = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_gid = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_pid = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					if ((bufp = strchr(buffer+length, '\0')) == NULL) {
						wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
						return -1;
					}
					strcpy (pktd_prot_filter, buffer+length);
					length = bufp + 1 - buffer;
					pktd_prot_snaplen = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_port = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_immediate_delivery = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_compression = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_co_rm_offset = 
							(u_int32_t)ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_co_ip_mask = *(u_int8_t *)(buffer+length);
					length += sizeof(u_int8_t);
					pktd_prot_co_tcp_mask = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_co_udp_mask = *(u_int8_t *)(buffer+length);
					length += sizeof(u_int8_t);
					break;

				case PROT_TYPE_WIRE_INIT_F:
					/* the client requested receiving packets in a file */
					pktd_prot_uid = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_gid = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_pid = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					if ((bufp = strchr(buffer+length, '\0')) == NULL) {
						wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
						return -1;
					}
					strcpy (pktd_prot_filter, buffer+length);
					length = bufp + 1 - buffer;
					pktd_prot_snaplen = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_cp_time = (u_int16_t)ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_cp_length = (u_int16_t)ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_cp_files = (u_int16_t)ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_immediate_delivery = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_compression = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_co_rm_offset = 
							(u_int32_t)ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_co_ip_mask = *(u_int8_t *)(buffer+length);
					length += sizeof(u_int8_t);
					pktd_prot_co_tcp_mask = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_co_udp_mask = *(u_int8_t *)(buffer+length);
					length += sizeof(u_int8_t);
					if ((bufp = strchr(buffer+length, '\0')) == NULL) {
						wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
						return -1;
					}
					strcpy (pktd_prot_file_pattern, buffer+length);
					length = bufp + 1 - buffer;
					break;

				case PROT_TYPE_WIRE_SETFILTER:
					/* the client requested changing its filter and/or snaplen */
					pktd_prot_cookie = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					if ((bufp = strchr(buffer+length, '\0')) == NULL) {
						wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
						return -1;
					}
					strcpy (pktd_prot_filter, buffer+length);
					length = bufp + 1 - buffer;
					pktd_prot_snaplen = ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_cp_time = (u_int16_t)ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_cp_length = (u_int16_t)ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					pktd_prot_cp_files = (u_int16_t)ntohs(*(u_int16_t *)(buffer+length));
					length += sizeof(u_int16_t);
					break;

				case PROT_TYPE_WIRE_DONE:
					/* the client requested closing his subfilter */
					pktd_prot_cookie = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_STATS:
					/* the client requested knowing the device packet statistics */
					pktd_prot_cookie = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_FLUSH:
					/* the client requested a buffer flush */
					pktd_prot_cookie = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_INJECT:
					/* the client requested to write a packet */
					pktd_prot_cookie = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					(void)memcpy (pktd_prot_ip, buffer+length, ntohs(*(u_int16_t*)
							(buffer+length+2)));
					length += ntohs(*(u_int16_t*)(buffer+length+2));
					break;

				default:
					/* the client sent a bad request */
					wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
					return -1;
					break;
			} /* switch (*command) */

		} else { /* request == 0 (i.e., answer) */
			switch (*command) {
				case PROT_TYPE_WIRE_INIT_P:
					/* the server ack'ed the command and added the cookie, datalink, 
					 * and hdr_size
					 */
					pktd_prot_cookie = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_datalink = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_hdr_size = (int) ntohl(*(int *)(buffer+length));
					length += sizeof(int);
					pktd_prot_ps_recv = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_ps_drop = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_ps_ifdrop = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_INIT_F:
					/* the server ack'ed the command and added the cookie */
					pktd_prot_cookie = (int) ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					if ((bufp = strchr(buffer+length, '\0')) == NULL) {
						wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
						return -1;
					}
					strcpy (pktd_prot_file_path, buffer+length);
					length = bufp + 1 - buffer;
					break;

				case PROT_TYPE_WIRE_SETFILTER:
					/* the server ack'ed the command */
					break;

				case PROT_TYPE_WIRE_DONE:
					/* the server accepted closing a client's subfilter */
					pktd_prot_ps_recv = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_ps_drop = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_ps_ifdrop = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_STATS:
					/* the server returns the device packet statistics */
					pktd_prot_ps_recv = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_ps_drop = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					pktd_prot_ps_ifdrop = ntohl(*(u_int32_t *)(buffer+length));
					length += sizeof(u_int32_t);
					break;

				case PROT_TYPE_WIRE_FLUSH:
					/* the server ack'ed a device flush */
					break;

				case PROT_TYPE_WIRE_INJECT:
					/* the server ack'ed the command */
					break;

				default:
					/* the server sent a bad answer */
					wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
					return -1;
					break;
			} /* switch (*command) */
		} /* *request != 0 (request) || request == 0 (answer)  */
	} /* *status == WIRE_ERR_NONE */

	return 0;
}




/*
 * pktd_server_socket
 *
 *	Opens a server socket that only accepts connections from the 
 *	local machine
 *
 * Inputs:
 *	- port: the port number. If is equal to 0 means "choose the number for me"
 *
 * Output:
 *	- return: a socket descriptor, <0 if there was any problem
 *
 */
int pktd_server_socket (u_int *port)
{
	struct sockaddr_in sin;
	int fd;
	int on = 1;
	socklen_t alen;

	/* create the socket */
	if ((fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		wire_errcode = WIRE_ERR_PROT_SOCKET;
		return -1;
	}

	/* configure it */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
		close(fd);
		wire_errcode = WIRE_ERR_PROT_SETSOCKOPT;
		return -1;
	}

	/* initialize sin structure and bind socket */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(*port);
	if (bind (fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		close(fd);
		wire_errcode = WIRE_ERR_PROT_BIND;
		return -1;
	}

	/* get the port in case we were asked to choose it */
	alen = sizeof(sin);
	if (getsockname (fd, (struct sockaddr*)&sin, &alen) < 0) {
		close(fd);
		wire_errcode = WIRE_ERR_PROT_GETSOCKNAME;
		return -1;
	}
	*port = ntohs(sin.sin_port);

	/* listen */
  if (listen(fd, QLEN) < 0) {
		close(fd);
		wire_errcode = WIRE_ERR_PROT_LISTEN;
		return -1;
	}

  return fd;
}




/*
 * pktd_client_socket
 *
 *	Opens a client socket to the local machine
 *
 * Inputs:
 *	- port: the port number
 *
 * Output:
 *	- return: a socket descriptor, <0 if there was any problem
 *
 */
int pktd_client_socket (u_int port)
{
	int fd;
	struct sockaddr_in saddr;


	/* create the socket */
	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		wire_errcode = WIRE_ERR_PROT_SOCKET;
		return -1;
	}

	/* connect it to the server */
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons (port);
	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		wire_errcode = WIRE_ERR_PROT_CONNECT;
		return -1;
	}

	return fd;
}




/*
 * pktd_write_header
 *
 * Description:
 *	- Writes a tcpdump header in network order
 *
 * Inputs:
 *	- fid: a file descriptor where to write the header
 *	- snaplen: the snaplen the packets where taken with
 *	- datalink: a datalink identifier
 *
 * Output:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_write_header (int fid, u_int snaplen, int datalink)
{
	struct pcap_file_header hdr;

	hdr.magic = htonl(TCPDUMP_MAGIC);
	hdr.version_major = htons(PCAP_VERSION_MAJOR);
	hdr.version_minor = htons(PCAP_VERSION_MINOR);

	/* this is indeed zero'ed in pcap and never set!! */
	hdr.thiszone = htonl(0);

	hdr.sigfigs = htonl(0);
	hdr.snaplen = htonl((u_int32_t)snaplen);
	hdr.linktype = htonl(datalink);

	if (write(fid, (char *)&hdr, sizeof(hdr)) < 0) {
		return -1;
	}

	return 0;
}




/*
 * pktd_lfwrite_ext_header
 *
 * Description:
 *	- Writes an extended pcap header in network order
 *
 * Inputs:
 *	- fp: an lstdio.h lFILE file pointer where to write the header
 *	- snaplen: the snaplen the packets where taken with
 *	- datalink: a datalink identifier
 *	- co: compression information (restart marker distance and masks)
 *	- filter: filter used to obtain the trace
 *
 * Output:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_lfwrite_ext_header (lFILE *fp, u_int snaplen, int datalink, co_t *co,
    char *filter)
{
	struct pcap_file_header hdr;
	u_char extended_header[1024];
	int i;

	/* pcap standard header */
	hdr.magic = htonl(TCPDUMP_MAGIC);
	hdr.version_major = htons(PCAP_VERSION_MAJOR);
	/* hdr.version_minor = htons(PCAP_VERSION_MINOR); */
	hdr.version_minor = htons(5);

	/* this is indeed zero'ed in pcap and never set!! */
	hdr.thiszone = htonl(0);

	hdr.sigfigs = htonl(0);
	hdr.snaplen = htonl((u_int32_t)snaplen);
	hdr.linktype = htonl(datalink);

	if (lfwrite(fp, (char *)&hdr, sizeof(hdr)) < 0) {
		return -1;
	}


	if (datalink == DLT_COMPRESSED) {
		/* pcap extended header */
		int len;

		i = 4;

		/* restart markers offset */
		*(extended_header+i) = (u_char)XT_PCAP_KIND_RM_OFFSET;
		i++;
		len = 4;
		*(extended_header+i) = (u_char)len;
		i++;
		*(u_int32_t *)(extended_header+i) = htonl(co->rm_offset);
		i += 4;

		/* IP compression mask */
		*(extended_header+i) = (u_char)XT_PCAP_KIND_IP_MASK;
		i++;
		len = 1;
		*(extended_header+i) = (u_char)len;
		i++;
		*(u_int8_t *)(extended_header+i) = co->ip_mask;
		i += 1;

		/* TCP compression mask */
		*(extended_header+i) = (u_char)XT_PCAP_KIND_TCP_MASK;
		i++;
		len = 2;
		*(extended_header+i) = (u_char)len;
		i++;
		*(u_int16_t *)(extended_header+i) = htons(co->tcp_mask);
		i += 2;

		/* UDP compression mask */
		*(extended_header+i) = (u_char)XT_PCAP_KIND_UDP_MASK;
		i++;
		len = 1;
		*(extended_header+i) = (u_char)len;
		i++;
		*(u_int8_t *)(extended_header+i) = co->udp_mask;
		i += 1;

		/* filter string */
		if (filter != NULL) {
			len = strlen (filter);
			if (len < 256) {
				*(extended_header+i) = (u_char)XT_PCAP_KIND_FILTER;
				i++;
				*(extended_header+i) = (u_char)len;
				i++;
				strncpy((char *)(extended_header+i), filter, len);
				i += len;
			}
		}

		/* options length */
		*(u_int32_t *)(extended_header+0) = htonl(i);

		if (lfwrite(fp, (char *)extended_header, i) < 0) {
			return -1;
		}
	}

	return 0;
}




/*
 * pktd_fread_header
 *
 * Description:
 *	- Reads a tcpdump header. Most of the code has been stolen from 
 *		libpcap's savefile.c:pcap_open_offline()
 *
 * Inputs:
 *	- fp: a file pointer where to write the header
 *
 * Output:
 *	- hdr: a pcap file header
 *	- swapped: whether the pcap file header was swapped
 *	- co: compression information (restart marker distance and masks)
 *	- filter: filter used to obtain the trace
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_fread_header (FILE *fp, struct pcap_file_header *hdr, int *swapped, 
		co_t *co, char *filter)
{
	u_int32_t magic;
	u_char extended_header[1024];
	u_int32_t len;
	int i;
	u_int kind, kind_len;

	if (fread((char *)hdr, sizeof(*hdr), 1, fp) != 1) {
		return -1;
	}

	*swapped = 0;
	magic = hdr->magic;
	if (magic != TCPDUMP_MAGIC) {
		magic = SWAPLONG(magic);
		if (magic != TCPDUMP_MAGIC) {
			return -1;
		}
		pktd_swap_filehdr (hdr);
		*swapped = 1;
	}

	if (hdr->version_minor == 5) {
		/* pcap extended header */

		/* options length */
		if (fread((char *)extended_header, sizeof(u_int32_t), 1, fp) != 1) {
			return -1;
		}
		len = ntohl(*(u_int32_t *)extended_header);
		i = 4;

		/* options */
		if (fread((char *)(extended_header+i), len-i, 1, fp) != 1) {
			return -1;
		}

		while (i < len) {
			kind = (u_int)*(extended_header+i);
			i++;
			switch (kind) {
				case XT_PCAP_KIND_IP_MASK:
					/* IP compression mask */
					kind_len = (u_int)*(extended_header+i);
					i += 1;
					co->ip_mask = *(u_int8_t *)(extended_header+i);
					i += kind_len;
					break;

				case XT_PCAP_KIND_TCP_MASK:
					/* TCP compression mask */
					kind_len = (u_int)*(extended_header+i);
					i += 1;
					co->tcp_mask = ntohs(*(u_int16_t *)(extended_header+i));
					i += kind_len;
					break;

				case XT_PCAP_KIND_UDP_MASK:
					/* UDP compression mask */
					kind_len = (u_int)*(extended_header+i);
					i += 1;
					co->udp_mask = *(u_int8_t *)(extended_header+i);
					i += kind_len;
					break;

				case XT_PCAP_KIND_RM_OFFSET:
					/* restart markers offset */
					kind_len = (u_int)*(extended_header+i);
					i += 1;
					co->rm_offset = ntohl(*(u_int32_t *)(extended_header+i));
					i += kind_len;
					break;

				case XT_PCAP_KIND_FILTER:
					/* restart markers offset */
					kind_len = (u_int)*(extended_header+i);
					i += 1;
					strncpy(filter, (const char *)(extended_header+i), kind_len);
					filter[kind_len] = '\0';
					i += kind_len;
					break;

				default:
					/* unrecognized option */
					kind_len = (u_int)*(extended_header+i);
					i += 1;
					i += kind_len;
			}
		}
	}


	return 0;
}




/*
 * pktd_swap_filehdr
 * pktd_swap_pkthdr
 * pktd_swap_packet
 *
 * Description:
 *	- Swaps a file header, packet header, and IP packet respectively
 *
 * Inputs:
 *	- filehdr: file header to be swapped
 *	- pkthdr: packet header to be swapped
 *	- packet: packet to be swapped
 *	- hdr_size: datalink header size
 *
 * Output:
 *
 */
void pktd_swap_filehdr (struct pcap_file_header *filehdr)
{
	filehdr->version_major = SWAPSHORT(filehdr->version_major);
	filehdr->version_minor = SWAPSHORT(filehdr->version_minor);
	filehdr->thiszone = SWAPLONG(filehdr->thiszone);
	filehdr->sigfigs = SWAPLONG(filehdr->sigfigs);
	filehdr->snaplen = SWAPLONG(filehdr->snaplen);
	filehdr->linktype = SWAPLONG(filehdr->linktype);
}


void pktd_swap_pkthdr (struct pcap_pkthdr *pkthdr)
{
	pkthdr->caplen = SWAPLONG(pkthdr->caplen);
	pkthdr->len = SWAPLONG(pkthdr->len);
	pkthdr->ts.tv_sec = SWAPLONG(pkthdr->ts.tv_sec);
	pkthdr->ts.tv_usec = SWAPLONG(pkthdr->ts.tv_usec);
}


void pktd_swap_packet (u_char *pkt, int hdr_length) 
{
	int ip_hdr_length;
	int transport_protocol;

	/* move to the IP header */
	pkt += hdr_length;

	/* check this is IPv4 */
	if ((((*(u_int8_t *)pkt) & 0xf0) >> 4) != 4) {
		return;
	}

	/* swap the IP length, id, frag, cksum, src addr, and dst addr */
	*(u_int16_t *)(pkt+2) = SWAPSHORT(*(u_int16_t *)(pkt+2));
	*(u_int16_t *)(pkt+4) = SWAPSHORT(*(u_int16_t *)(pkt+4));
	*(u_int16_t *)(pkt+6) = SWAPSHORT(*(u_int16_t *)(pkt+6));
	*(u_int16_t *)(pkt+10) = SWAPSHORT(*(u_int16_t *)(pkt+10));
	*(u_int32_t *)(pkt+12) = SWAPLONG(*(u_int32_t *)(pkt+12));
	*(u_int32_t *)(pkt+16) = SWAPLONG(*(u_int32_t *)(pkt+16));

	ip_hdr_length = ((*(u_int8_t *)pkt) & 0x0f) << 2;
	transport_protocol = *(u_int8_t *)(pkt+9);
	pkt += ip_hdr_length;

	switch (transport_protocol) {
		case IPPROTO_TCP:
			/* swap TCP src port, dst port, seq#, ack#, window size, cksum, urg ptr */
			*(u_int16_t *)(pkt+0) = SWAPSHORT(*(u_int16_t *)(pkt+0));
			*(u_int16_t *)(pkt+2) = SWAPSHORT(*(u_int16_t *)(pkt+2));
			*(u_int32_t *)(pkt+4) = SWAPLONG(*(u_int32_t *)(pkt+4));
			*(u_int32_t *)(pkt+8) = SWAPLONG(*(u_int32_t *)(pkt+8));
			*(u_int16_t *)(pkt+14) = SWAPSHORT(*(u_int16_t *)(pkt+14));
			*(u_int16_t *)(pkt+16) = SWAPSHORT(*(u_int16_t *)(pkt+16));
			*(u_int16_t *)(pkt+18) = SWAPSHORT(*(u_int16_t *)(pkt+18));

			/* XXX: maybe should swap options */

		case IPPROTO_UDP:
			/* swap UDP src port, dst port, length, cksum */
			*(u_int16_t *)(pkt+0) = SWAPSHORT(*(u_int16_t *)(pkt+0));
			*(u_int16_t *)(pkt+2) = SWAPSHORT(*(u_int16_t *)(pkt+2));
			*(u_int16_t *)(pkt+4) = SWAPSHORT(*(u_int16_t *)(pkt+4));
			*(u_int16_t *)(pkt+6) = SWAPSHORT(*(u_int16_t *)(pkt+6));
			break;

		case IPPROTO_ICMP:
			printf ("ICMP: not yet\n");
			break;

		default:
			/* swap other network-layer header */
			printf ("Unknown transport protocol: %i\n", transport_protocol);
			break;
	}

	return;
}




/*
 * pktd_get_hdr_size
 *
 *  Get the header size for a given datalink type
 *
 * Inputs:
 *  - datalink: datalink type
 *
 * Output:
 *  - return: header size if correct, <0 if there were problems
 *
 */
int pktd_get_hdr_size (int datalink)
{
	switch (datalink) {
		case DLT_RAW:
			/* raw IP (no link layer) */
			return 0;
			break;

		case DLT_NULL:
			/* FreeBSD localhost link layer size */
			return 4;
			break;

		case DLT_EN10MB:
			return 14;
			break;

		case DLT_FDDI:
			/* fddi_header + LLC */
			return (13 + 8);
			break;

		default:
			return -1;
	}

	return 0;
}


/*
 * protocol.h --
 *
 *  PKTD daemon: client-server protocol header
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


#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#if defined(__linux__)
#include "bpf.h"
#elif (defined(__svr4__) || defined(__SVR4))
#include "bpf.h"
#else
#include <net/bpf.h>
#include <pcap.h>
#endif 

#include <pcap-int.h>

#include <semaphore.h>

#include "lstdio.h"

#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif


/* compressed tcpdump file */
#define DLT_COMPRESSED  0xc0

/* compression info */
typedef struct {
  /* trace compression restart marker */
  u_int32_t rm_offset;
  /* trace compression mask */
  u_int8_t ip_mask;
  u_int16_t tcp_mask;
  u_int8_t udp_mask;
} co_t;



/* tcpdump magic header */
#define TCPDUMP_MAGIC 0xa1b2c3d4

/* maximum connection queue length */
#define QLEN 5

/* some control-protocol data */
#define PROT_SERVERPORT 12345
#define PROT_MINHEADER 4
#define PROT_MAXLENGTH 4096
#define PROT_VERSION (u_int8_t)0x10
#define PROT_TYPE_ANSWER                (u_int8_t)0x00
#define PROT_TYPE_REQUEST               (u_int8_t)0x01
#define PROT_TYPE_WIRE_INIT_P           (u_int8_t)0x00
#define PROT_TYPE_WIRE_INIT_F           (u_int8_t)0x01
#define PROT_TYPE_WIRE_DONE             (u_int8_t)0x02
#define PROT_TYPE_WIRE_SETFILTER        (u_int8_t)0x03
#define PROT_TYPE_WIRE_STATS            (u_int8_t)0x04
#define PROT_TYPE_WIRE_INJECT           (u_int8_t)0x05
#define PROT_TYPE_WIRE_FLUSH            (u_int8_t)0x06
#define PROT_STATUS_OK                  0


/* some control-protocol limitations: maximum file name length, maximum 
	filter length, and maximum IP packet length */
#define PROT_MAXFILENAME 1024
#define PROT_MAX_INDIVIDUAL_FILTER 256
#define PROT_MAX_IP_LENGTH 65535


/* some data-protocol data */
/* the maximum buffer size was obtained from pcap (pcap-bpf.c:189) */
#define MAXDATABUFFER 32768

/* tcpdump adds a 16-byte long header per packet: sec, usec, caplen, len */
#define TCPDUMP_PACKET_HEADER_LENGTH 16

/* compressed-packet header length */
#define TCPDUMP_PACKET_HEADER_LENGTH_COMPRESSED 1


/* variables used by pktd_recv to pass request arguments up */
extern u_int32_t pktd_prot_cookie;
extern char pktd_prot_filter[PROT_MAX_INDIVIDUAL_FILTER];
extern char pktd_prot_file_path[PROT_MAXFILENAME];
extern char pktd_prot_file_pattern[PROT_MAXFILENAME];
extern u_int pktd_prot_port;
extern int pktd_prot_immediate_delivery;
extern int pktd_prot_compression;
extern u_int pktd_prot_snaplen;
extern u_int16_t pktd_prot_cp_time;
extern u_int16_t pktd_prot_cp_length;
extern u_int16_t pktd_prot_cp_files;
extern u_int8_t pktd_prot_co_ip_mask;
extern u_int16_t pktd_prot_co_tcp_mask;
extern u_int8_t pktd_prot_co_udp_mask;
extern u_int32_t pktd_prot_co_rm_offset;
extern u_int32_t pktd_prot_ps_recv;
extern u_int32_t pktd_prot_ps_drop;
extern u_int32_t pktd_prot_ps_ifdrop;
extern u_int32_t pktd_prot_uid, pktd_prot_gid, pktd_prot_pid;
extern u_int32_t pktd_prot_datalink;
extern int pktd_prot_hdr_size;
extern char pktd_prot_ip[PROT_MAX_IP_LENGTH];



/* exported procedures */
#if __STDC__
int pktd_send (int fd, int request, int command, int status, ...);
#else
int pktd_send (fd, request, command, status, va_alist);
#endif
int pktd_recv (int fd, int *request, int *command, int *status);
int pktd_server_socket (u_int *port);
int pktd_client_socket (u_int port);
int pktd_write_header (int fid, u_int snaplen, int datalink);
int pktd_lfwrite_ext_header (lFILE *fp, u_int snaplen, int datalink, co_t *co, 
		char *filter);
int pktd_fread_header (FILE *fp, struct pcap_file_header *hdr, int *swapped,
    co_t *co, char *filter);
int pktd_get_hdr_size (int datalink);
void pktd_swap_filehdr (struct pcap_file_header *filehdr);
void pktd_swap_pkthdr (struct pcap_pkthdr *pkthdr);
void pktd_swap_packet (u_char *pkt, int hdr_length);


#define SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff)) 
#define SWAPSHORT(y) \
	( (((y)&0xff)<<8) | ((u_short)((y)&0xff00)>>8) )



/* exported error variable, message, and possible values */
extern int wire_errcode;
const char *wire_err_msg ();

#define WIRE_ERR_NONE                                   0

#define WIRE_ERR_LOCAL_OTHER                            1|0x00
#define WIRE_ERR_LOCAL_OUT_OF_MEMORY                    2|0x00
#define WIRE_ERR_LOCAL_NO_SUCH_FILE                     3|0x00
#define WIRE_ERR_LOCAL_FILTER                           4|0x00
#define WIRE_ERR_LOCAL_INTERNAL                         5|0x00
#define WIRE_ERR_LOCAL_UNKNOWN_LINK_TYPE                6|0x00
#define WIRE_ERR_LOCAL_EXCESSIVE_FILTER                 7|0x00
#define WIRE_ERR_LOCAL_PCAP                             8|0x00
#define WIRE_ERR_LOCAL_CANT_OPEN_FILE                   9|0x00
#define WIRE_ERR_LOCAL_CANT_OPEN_TRACE_FILE            10|0x00
#define WIRE_ERR_LOCAL_CANT_OPEN_FILTER                11|0x00
#define WIRE_ERR_LOCAL_CANT_OPEN_FILTER_NO_PERMISSION  12|0x00
#define WIRE_ERR_LOCAL_ILLEGAL_PATTERN                 13|0x00
#define WIRE_ERR_LOCAL_IMMEDIATE_MODE                  14|0x00
#define WIRE_ERR_LOCAL_NO_PKTD_SOCKET                 15|0x00

#define WIRE_ERR_PROT_OTHER                             1|0x40
#define WIRE_ERR_PROT_UNRECOGNIZED_COMMAND             32|0x40
#define WIRE_ERR_PROT_BAD_FORMED_REQUEST               33|0x40
#define WIRE_ERR_PROT_MISBEHAVING_CLIENT               34|0x40
#define WIRE_ERR_PROT_SOCKET                           35|0x40
#define WIRE_ERR_PROT_SETSOCKOPT                       36|0x40
#define WIRE_ERR_PROT_BIND                             37|0x40
#define WIRE_ERR_PROT_GETSOCKNAME                      38|0x40
#define WIRE_ERR_PROT_LISTEN                           39|0x40
#define WIRE_ERR_PROT_CONNECT                          40|0x40
#define WIRE_ERR_PROT_SENDING_COMMAND                  42|0x40
#define WIRE_ERR_PROT_SENDING_DATA                     43|0x40
#define WIRE_ERR_PROT_PERMISSION                       44|0x40
#define WIRE_ERR_PROT_CANNOT_WRITE_FILE                45|0x40
#define WIRE_ERR_PROT_ILLEGAL_PATTERN                  46|0x40
#define WIRE_ERR_PROT_INTERNAL_PROBLEMS                47|0x40

#define WIRE_ERR_PKTD_OTHER                            1|0x80
#define WIRE_ERR_PKTD_OUT_OF_MEMORY                    2|0x80
#define WIRE_ERR_PKTD_NO_SUCH_FILE                     3|0x80
#define WIRE_ERR_PKTD_FILTER                           4|0x80
#define WIRE_ERR_PKTD_INTERNAL                         5|0x80
#define WIRE_ERR_PKTD_UNKNOWN_LINK_TYPE                6|0x80
#define WIRE_ERR_PKTD_EXCESSIVE_FILTER                 7|0x80
#define WIRE_ERR_PKTD_PCAP                             8|0x80
#define WIRE_ERR_PKTD_CANT_OPEN_FILE                   9|0x80
#define WIRE_ERR_PKTD_CANT_OPEN_TRACE_FILE            10|0x80
#define WIRE_ERR_PKTD_CANT_OPEN_FILTER                11|0x80
#define WIRE_ERR_PKTD_CANT_OPEN_FILTER_NO_PERMISSION  12|0x80
#define WIRE_ERR_PKTD_ILLEGAL_PATTERN                 13|0x80
#define WIRE_ERR_PKTD_IMMEDIATE_MODE                  14|0x80

#define WIRE_ERR_PKTD_TOO_MANY_CLIENTS                15|0x80
#define WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_FILTER      16|0x80
#define WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_WRITE       17|0x80
#define WIRE_ERR_PKTD_WRITE_DISABLED                  18|0x80
#define WIRE_ERR_PKTD_NO_WRITE_DEVICE_ACCESS          19|0x80
#define WIRE_ERR_PKTD_INJECTION_OPEN                  20|0x80
#define WIRE_ERR_PKTD_INJECTION_WRITE_IP              21|0x80
#define WIRE_ERR_PKTD_INJECTION_CLOSE                 22|0x80
#define WIRE_ERR_PKTD_BAD_COOKIE                      23|0x80
#define WIRE_ERR_PKTD_NO_DEVICE                       24|0x80


/* read errors */
#define WIRE_READ_ERROR      -3
#define WIRE_READ_EOF        -2
#define WIRE_READ_INCOMPLETE -1


/* extended pcap header kinds */
#define XT_PCAP_KIND_END 0
#define XT_PCAP_KIND_DROPS 1
#define XT_PCAP_KIND_FILTER 2
#define XT_PCAP_KIND_RM_OFFSET 3
#define XT_PCAP_KIND_IP_MASK 4
#define XT_PCAP_KIND_TCP_MASK 5
#define XT_PCAP_KIND_UDP_MASK 6

#endif


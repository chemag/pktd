/*
 * trace-codec.h
 *
 *       Trace Encoder and Decoder header file
 *
 * Copyright (c) 2001 - 2002 The International Computer Science Institute
 * Copyright (c) 2002 - 2002 Lawrence Berkeley National Laboratory
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


#ifndef _TRACE_CODEC_H
#define _TRACE_CODEC_H


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "lstdio.h"
#include "protocol.h"


/* maximum size of a compressed packet */
#define MAX_COMPRESSED_LENGTH 256


/* escaped packet lengths */
#define COMPRESSION_INIT_CODEC 0x00
#define COMPRESSION_PADDING 0x01


/* maximum sizes of IP and network-layer headers */
#define CACHE_MAX_IP_HEADER 40
#define CACHE_MAX_NL_HEADER 60


/* default compression parameters  (no checksums) */
#define DEFAULT_PKTD_COMPRESSION_IP_MASK 0xfb
#define DEFAULT_PKTD_COMPRESSION_TCP_MASK 0xfeff
#define DEFAULT_PKTD_COMPRESSION_UDP_MASK 0xef
#define DEFAULT_PKTD_COMPRESSION_RESTART_MARKER 8192


/* IP mask flags */
#define MASK_FLAG_IP_VLT 0x80
#define MASK_FLAG_IP_LEN 0x40
#define MASK_FLAG_IP_IDN 0x20
#define MASK_FLAG_IP_FRA 0x10
#define MASK_FLAG_IP_TAP 0x08
#define MASK_FLAG_IP_ICK 0x04
#define MASK_FLAG_IP_SAD 0x02
#define MASK_FLAG_IP_DAD 0x01


/* TCP mask flags */
#define MASK_FLAG_TCP_TSP 0x08
#define MASK_FLAG_TCP_TDP 0x04
#define MASK_FLAG_TCP_SEQ 0x02
#define MASK_FLAG_TCP_ACK 0x01

#define MASK_FLAG_TCP_HF1 0x80
#define MASK_FLAG_TCP_HF2 0x40
#define MASK_FLAG_TCP_WIN 0x20
#define MASK_FLAG_TCP_TCK 0x10
#define MASK_FLAG_TCP_URG 0x08
#define MASK_FLAG_TCP_OPT 0x04


/* UDP mask flags */
#define MASK_FLAG_UDP_USP 0x08
#define MASK_FLAG_UDP_UDP 0x04
#define MASK_FLAG_UDP_ULN 0x02
#define MASK_FLAG_UDP_UCK 0x01



/* maximum number of connections (the last one is used by other network-layer
 * packets) */
#define CACHE_MAX_TCP_CONN 8
#define CACHE_MAX_UDP_CONN 8
#define CACHE_MAX_CONN (CACHE_MAX_UDP_CONN + CACHE_MAX_TCP_CONN + 1)


/* codec structure */
struct s_codec_t {
	struct pcap_pkthdr last_pcap_hdr;
	/* IP header: 20 typical plus another 20 for options (rare) */
	u_char last_ip_hdr[CACHE_MAX_CONN][40];
	/* Network-layer hedaer: need 8 for UDP, 20 (typical) plus 20 (options) 
	  for TCP */
	u_char last_nl_hdr[CACHE_MAX_CONN][40];
	u_long lru_time[CACHE_MAX_CONN];
	u_long current_time;
};
typedef struct s_codec_t codec_t;


/* codec creator and initializer */
codec_t *create_codec ();
void init_codec (codec_t *codec);


/* packet encoder */
int encode_trace (codec_t *codec, co_t *co,
		const struct pcap_pkthdr *pcap_hdr, const u_char *pkt, u_int caplen, 
		int datalink_hdr_length, u_char **comp_pkt, int *comp_len);


/* packet decoder */
int decode_trace (codec_t *codec, u_char *compressed_buffer, 
		struct pcap_pkthdr *pcap_hdr, u_char *pkt);


/* restart markers and padding insertion */
int need_restart_markers (co_t *co, lFILE *fp, int len,
		u_int32_t bytes_written, codec_t *codec);



#define IP_CHECKSUM(buffer, length, ck_sum)      \
{                                                \
	int j;                                         \
	register u_int32_t sum;                        \
	                                               \
	sum = 0;                                       \
	/* make 16 bit words out of every two adjacent \
	 * bytes, and add them up */                   \
	for (j = 0; j < length; j = j + 2) {           \
		if (j != 10) {                               \
			sum += (u_int32_t)*(u_int16_t *)(buffer+j);\
		}                                            \
	}                                              \
	                                               \
	/* take only 16 bits out of the 32 bit sum and \
	 * add up the carries */                       \
	while ((sum >> 16) != 0) {                     \
		sum = (sum & 0xffff) + (sum >> 16);          \
	}                                              \
	                                               \
	/* one's complement the result */              \
	ck_sum = (u_int16_t)(~sum & 0xffff);           \
}



#define UDP_CHECKSUM(buffer, ip_length, ck_sum)         \
{                                                       \
	register u_int32_t sum;                               \
	                                                      \
	sum = 0;                                              \
	/* make 16 bit words out of every two adjacent        \
	 * bytes of the pseudoheader, and add them up */      \
	sum += (u_int32_t)*(u_int8_t *)(buffer+9);            \
	sum += (u_int32_t)*(u_int16_t *)(buffer+12);          \
	sum += (u_int32_t)*(u_int16_t *)(buffer+14);          \
	sum += (u_int32_t)*(u_int16_t *)(buffer+16);          \
	sum += (u_int32_t)*(u_int16_t *)(buffer+18);          \
	sum += (u_int32_t)*(u_int16_t *)(buffer+ip_length+4); \
	                                                      \
	/* make 16 bit words out of every two adjacent        \
	 * bytes of the UDP header, and add them up */        \
	sum += (u_int32_t)*(u_int16_t *)(buffer+ip_length+0); \
	sum += (u_int32_t)*(u_int16_t *)(buffer+ip_length+2); \
	sum += (u_int32_t)*(u_int16_t *)(buffer+ip_length+4); \
	sum += (u_int32_t)*(u_int16_t *)(buffer+ip_length+6); \
	                                                      \
	/* take only 16 bits out of the 32 bit sum and        \
	 * add up the carries */                              \
	while ((sum >> 16) != 0) {                            \
		sum = (sum & 0xffff) + (sum >> 16);                 \
	}                                                     \
	                                                      \
	/* one's complement the result */                     \
	ck_sum = (u_int16_t)(~sum & 0xffff);                  \
}


#endif


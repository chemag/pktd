/*
 * trace-codec.c
 *
 *       Trace Encoder and Decoder
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>

#if defined(__sun__)
#include "bpf.h"
#else
#include <net/bpf.h>
#include <pcap.h>
#endif


#include "lstdio.h"
#include "trace-codec.h"
#include "daemon.h"


int get_cache_conn_id (codec_t *codec, const u_char *ip_hdr);
struct timeval ts_add (const struct timeval *ts, const long amount);
long ts_sub (const struct timeval *tsa, const struct timeval *tsb);


#define ISSET(set,flag) (((set & flag) == 0) ? 0 : 1)
#define MAXIMUM(a,b) ((a) > (b) ? (a) : (b))
#define MINIMUM(a,b) ((a) > (b) ? (b) : (a))




/*
 * create_codec
 *
 * Description:
 *  - Codec constructor. Creates codec structures and inits them
 *
 * Inputs:
 *
 * Outputs:
 *  - result: the resulting codec  
 *
 */
codec_t *create_codec ()
{
	codec_t *codec;

	codec = (codec_t *) malloc (sizeof(codec_t));
	init_codec (codec);

	return codec;
}




/*
 * init_codec
 *
 * Description:
 *  - Codec initializer. Zeroes the codec structures
 *
 * Inputs:
 *  - codec: the codec to initialize
 *
 * Outputs:
 *
 */
void init_codec (codec_t *codec)
{
	int cid;

	/* init last pcap header */
	codec->last_pcap_hdr.ts.tv_sec = 0;
	codec->last_pcap_hdr.ts.tv_usec = 0;
	codec->last_pcap_hdr.caplen = 0;
	codec->last_pcap_hdr.len = 0;

	/* init last IP and network-layer headers, and the LRU registers */
	for (cid=0; cid<CACHE_MAX_CONN; cid++) {
		bzero(codec->last_ip_hdr[cid], CACHE_MAX_IP_HEADER);
		codec->last_ip_hdr[cid][0] = 0x45;
		bzero(codec->last_nl_hdr[cid], CACHE_MAX_NL_HEADER);
		codec->lru_time[cid] = 0;
	}

	codec->current_time = 0;
}



#define CACHE_HIT(iph, nlh, ip_fragment, cid)                                 \
	(ip_fragment) ?                                                             \
	((*(u_int32_t *)(iph+12) == *(u_int32_t *)(codec->last_ip_hdr[cid]+12)) &&  \
		(*(u_int32_t *)(iph+16) == *(u_int32_t *)(codec->last_ip_hdr[cid]+16)) && \
		(0 == *(u_int16_t *)(codec->last_nl_hdr[cid]+0)) &&                       \
		(0 == *(u_int16_t *)(codec->last_nl_hdr[cid]+2))) :                       \
	((*(u_int32_t *)(iph+12) == *(u_int32_t *)(codec->last_ip_hdr[cid]+12)) &&  \
		(*(u_int32_t *)(iph+16) == *(u_int32_t *)(codec->last_ip_hdr[cid]+16)) && \
		(*(u_int16_t *)(nlh+0) == *(u_int16_t *)(codec->last_nl_hdr[cid]+0)) &&   \
		(*(u_int16_t *)(nlh+2) == *(u_int16_t *)(codec->last_nl_hdr[cid]+2)))



#define OLDEST_CID(cid1, cid2)                                  \
	(codec->lru_time[cid1] <= codec->lru_time[cid2]) ? cid1 : cid2



#define GET_CID(ip_hdr_mask, buffer, cid)                  \
{                                                          \
	int index = 0;                                           \
	index += (ISSET(ip_hdr_mask, MASK_FLAG_IP_VLT)) ? 2 : 0; \
	index += (ISSET(ip_hdr_mask, MASK_FLAG_IP_LEN)) ? 2 : 0; \
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_IDN)) {              \
		if (*(u_int8_t *)(buffer+index) == 0) {                \
			index += 3;                                          \
		} else {                                               \
			index += 1;                                          \
		}                                                      \
	}                                                        \
	index += (ISSET(ip_hdr_mask, MASK_FLAG_IP_FRA)) ? 2 : 0; \
	index += (ISSET(ip_hdr_mask, MASK_FLAG_IP_TAP)) ? 2 : 0; \
	index += (ISSET(ip_hdr_mask, MASK_FLAG_IP_ICK)) ? 2 : 0; \
	index += (ISSET(ip_hdr_mask, MASK_FLAG_IP_SAD)) ? 4 : 0; \
	index += (ISSET(ip_hdr_mask, MASK_FLAG_IP_DAD)) ? 4 : 0; \
	cid = ((*(u_int8_t *)(buffer+index)) & 0xf0) >> 4;       \
}




/*
 * get_cache_conn_id
 *
 * Description:
 *  - Given a codec and a packet (ip_hdr), gives the connection id of the 
 *		packet (cid). It also updates the cache position timing.
 *
 * Inputs:
 *  - codec: the codec  
 *  - ip_hdr: the packet's IP header
 *
 * Outputs:
 *  - result: the connection id  
 *
 */
int get_cache_conn_id (codec_t *codec, const u_char *ip_hdr)
{
	int cid, oldest_cid;
	u_char *nl_hdr;
	int ip_fragment;

	nl_hdr = (u_char *)ip_hdr + (((*(u_int8_t *)(ip_hdr+0)) & 0x0f) << 2);
	if (codec->current_time == 0xffffffff) {
		codec->current_time = 0;
		for (cid=0; cid<CACHE_MAX_CONN; cid++) {
			codec->lru_time[cid] = 0;
		}
	} else {
		codec->current_time++;
	}

	ip_fragment = 0;
	if ((ntohs(*(u_int16_t *)(ip_hdr+6)) & 0x1fff) != 0)  {
		/* fragmentation (no first fragment) */
		ip_fragment = 1;
	}

	switch (*(u_int8_t *)(ip_hdr+9)) {
		case IPPROTO_TCP:
			oldest_cid = 0;
			for (cid=0; cid < CACHE_MAX_TCP_CONN; cid++) {
				if (CACHE_HIT(ip_hdr, nl_hdr, ip_fragment, cid)) {
					codec->lru_time[cid] = codec->current_time;
					return cid;
				}
				oldest_cid = OLDEST_CID(oldest_cid, cid);
			}
			cid = oldest_cid;
			codec->lru_time[cid] = codec->current_time;
			break;

		case IPPROTO_UDP:
			oldest_cid = CACHE_MAX_TCP_CONN;
			for (cid=CACHE_MAX_TCP_CONN; cid < (CACHE_MAX_CONN-1); cid++) {
				if (CACHE_HIT(ip_hdr, nl_hdr, ip_fragment, cid)) {
					codec->lru_time[cid] = codec->current_time;
					return cid;
				}
				oldest_cid = OLDEST_CID(oldest_cid, cid);
			}
			cid = oldest_cid;
			codec->lru_time[cid] = codec->current_time;
			break;

		default:
			cid = CACHE_MAX_CONN - 1;
			codec->lru_time[cid] = codec->current_time;
			break;
	}

	return cid;
}




/*
 * encode_trace
 *
 * Description:
 *  - Given a codec, a packet, and information about the underlying 
 *		datalink, encodes the packet.
 *
 * Inputs:
 *  - codec: codec  
 *  - co: compression parameters
 *  - pcap_hdr: packet information (timestamp, caplen, length)
 *  - pkt: pointer to the packet's datalink header
 *  - caplen: client's requested captured length
 *  - datalink_hdr_length: datalink header length
 *  - comp_pkt: compressed packet
 *  - comp_len: length of the compressed packet
 *
 * Outputs:
 *  - result: 0 if OK, < 0 otherwise  
 *
 */
int encode_trace (codec_t *codec, co_t *co,
		const struct pcap_pkthdr *pcap_hdr, 
		const u_char *pkt, u_int caplen, int datalink_hdr_length, 
		u_char **comp_pkt, int *comp_len)
{
	long ts_diff;
	u_int8_t i, ii;
	static u_char packet[99];
	u_char *ip_hdr;
	int cid;
	u_int8_t ip_hdr_mask;
	u_int16_t ip_hdr_length, ip_total_length;
	u_int16_t ip_id_diff;
	u_int8_t transport_protocol;
	u_int16_t ip_ck_sum;
	int ip_fragment;
	u_int8_t nl_hdr_mask;
	u_char *nl_hdr;
	u_int16_t udp_ck_sum;
	u_int8_t nl_hdr_mask2;
	u_int8_t tcp_hdr_length;
	u_long diff;
	u_int16_t tcp_ck_sum;


	/* initialize the result */
	i = 1;


	/* compress pcap header */
	/* YYY: it may be of interest to permit the client not compressing 
	 * timestamps. This'll mean ts_mask along with ip_mask, tcp_mask, and 
	 * udp_mask */
	ts_diff = ts_sub (&(pcap_hdr->ts), &(codec->last_pcap_hdr.ts));
	if ((0 <= ts_diff) && (ts_diff <= 253)) {
		/* one byte with unsigned difference */
		*(u_int8_t *)(packet+i) = (u_int8_t)ts_diff;
		i++;
		
	} else if ((0 <= ts_diff) && (ts_diff <= 65535)) {
		/* 0xfe + 2 bytes with unsigned difference */
		*(u_char *)(packet+i) = 0xfe;
		i++;
		*(u_int16_t *)(packet+i) = htons((u_int16_t)ts_diff);
		i += 2;

	} else {
		/* 0xff + 8 bytes with full timestamp */
		*(u_char *)(packet+i) = 0xff;
		i++;
		*(long *)(packet+i) = htonl((long)pcap_hdr->ts.tv_sec);
		i += 4;
		*(long *)(packet+i) = htonl((long)pcap_hdr->ts.tv_usec);
		i += 4;
	}
	codec->last_pcap_hdr = *pcap_hdr;


	/* throw away datalink header */
	pkt += datalink_hdr_length;


	/* compress IP header */
	ip_hdr_mask = 0;
	ip_hdr = (u_char *)pkt;
	cid = get_cache_conn_id (codec, ip_hdr);
	ii = i++;


	/* version, length, and type of service */
	if (ISSET(co->ip_mask, MASK_FLAG_IP_VLT) &&
			(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+0))) {
		ip_hdr_mask |= MASK_FLAG_IP_VLT;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	ip_hdr_length = ((*(u_int8_t *)pkt) & 0x0f) << 2;
	pkt += 2;

	/* total length */
	if (ISSET(co->ip_mask, MASK_FLAG_IP_LEN) &&
			(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+2))) {
		ip_hdr_mask |= MASK_FLAG_IP_LEN;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	ip_total_length = ntohs(*(u_int16_t *)pkt);
	pkt += 2;

	/* IP identification */
	if (ISSET(co->ip_mask, MASK_FLAG_IP_IDN) &&
			(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+4))) {
		ip_hdr_mask |= MASK_FLAG_IP_IDN;
		ip_id_diff = ntohs(*(u_int16_t *)pkt) - 
				ntohs(*(u_int16_t *)(codec->last_ip_hdr[cid]+4));
		if (ip_id_diff <= 255) {
			*(u_int8_t *)(packet+i) = (u_int8_t)(ip_id_diff);
			i++;
		} else {
			*(u_int8_t *)(packet+i) = 0;
			i++;
			*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
			i += 2;
		}
	}
	pkt += 2;

	/* DF, MF, and fragment offset */
	ip_fragment = 0;
	if (ISSET(co->ip_mask, MASK_FLAG_IP_FRA) &&
			(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+6))) {
		ip_hdr_mask |= MASK_FLAG_IP_FRA;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	if ((ntohs(*(u_int16_t *)pkt) & 0x1fff) != 0)  {
		/* fragmentation (no first fragment) */
		ip_fragment = 1;
	}
	pkt += 2;

	/* TTL and transport protocol */
	if (ISSET(co->ip_mask, MASK_FLAG_IP_TAP) &&
			(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+8))) {
		ip_hdr_mask |= MASK_FLAG_IP_TAP;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	transport_protocol = *(u_int8_t *)(pkt+1);
	pkt += 2;

	/* checksum */
	if (ISSET(co->ip_mask, MASK_FLAG_IP_ICK)) {
		IP_CHECKSUM(ip_hdr, ip_hdr_length, ip_ck_sum);
		if (*(u_int16_t *)pkt != ip_ck_sum) {
			ip_hdr_mask |= MASK_FLAG_IP_ICK;
			*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
			i += 2;
		}
	}
	pkt += 2;

	/* source address */
	if (ISSET(co->ip_mask, MASK_FLAG_IP_SAD) &&
			(*(u_int32_t *)pkt != *(u_int32_t *)(codec->last_ip_hdr[cid]+12))) {
		ip_hdr_mask |= MASK_FLAG_IP_SAD;
		*(u_int32_t *)(packet+i) = *(u_int32_t *)pkt;
		i += 4;
	}
	pkt += 4;

	/* destination address */
	if (ISSET(co->ip_mask, MASK_FLAG_IP_DAD) &&
			(*(u_int32_t *)pkt != *(u_int32_t *)(codec->last_ip_hdr[cid]+16))) {
		ip_hdr_mask |= MASK_FLAG_IP_DAD;
		*(u_int32_t *)(packet+i) = *(u_int32_t *)pkt;
		i += 4;
	}
	pkt += 4;

	/* IP options */
	if (ip_hdr_length > 20) {
		bcopy (pkt, packet, ip_hdr_length - 20);
		i += ip_hdr_length - 20;
		pkt += ip_hdr_length - 20;
	}


	/* copy the IP header mask */
	packet[ii] = ip_hdr_mask;

	bcopy (ip_hdr, codec->last_ip_hdr[cid], 20);


	/* compress transport-layer header */
	switch (transport_protocol) {
		case IPPROTO_TCP:
			/* compress TCP header */
			nl_hdr_mask = (cid&0x07)<<4;
			ii = i++;
			if (ip_fragment == 1) {
				/* a packet from a fragmented datagram (except the first fragment)
				 * has no transport-layer header => add only the cid */
				break;
			}
			nl_hdr = (u_char *)pkt;

			nl_hdr_mask2 = 0;
			i++;

			/* source port number */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_TSP) &&
					(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_nl_hdr[cid]+0))) {
				nl_hdr_mask |= MASK_FLAG_TCP_TSP;
				*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
				i += 2;
			}
			pkt += 2;

			/* destination port number */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_TDP) &&
					(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_nl_hdr[cid]+2))) {
				nl_hdr_mask |= MASK_FLAG_TCP_TDP;
				*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
				i += 2;
			}
			pkt += 2;

			/* sequence number */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_SEQ) &&
					(*(u_int32_t *)pkt != *(u_int32_t *)(codec->last_nl_hdr[cid]+4))) {
				nl_hdr_mask |= MASK_FLAG_TCP_SEQ;
				diff = ntohl(*(u_int32_t *)pkt) - 
						ntohl(*(u_int32_t *)(codec->last_nl_hdr[cid]+4));
				if ((diff > 0) && (diff <= 0xffff)) {
					*(u_int16_t *)(packet+i) = htons((u_int16_t)diff);
					i += 2;
				} else {
					*(u_int8_t *)(packet+i) = 0;
					i++;
					*(u_int8_t *)(packet+i) = 0;
					i++;
					*(u_int32_t *)(packet+i) = *(u_int32_t *)pkt;
					i += 4;
				}
			}
			pkt += 4;

			/* acknowledgment number */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_ACK) &&
					(*(u_int32_t *)pkt != *(u_int32_t *)(codec->last_nl_hdr[cid]+8))) {
				nl_hdr_mask |= MASK_FLAG_TCP_ACK;
				diff = ntohl(*(u_int32_t *)pkt) - 
						ntohl(*(u_int32_t *)(codec->last_nl_hdr[cid]+8));
				if ((diff > 0) && (diff <= 0xffff)) {
					*(u_int16_t *)(packet+i) = htons((u_int16_t)diff);
					i += 2;
				} else {
					*(u_int8_t *)(packet+i) = 0;
					i++;
					*(u_int8_t *)(packet+i) = 0;
					i++;
					*(u_int32_t *)(packet+i) = *(u_int32_t *)pkt;
					i += 4;
				}
			}
			pkt += 4;

			/* first header/reserved/flags byte */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_HF1) &&
					(*(u_int8_t *)pkt != *(u_int8_t *)(codec->last_nl_hdr[cid]+12))) {
				nl_hdr_mask2 |= MASK_FLAG_TCP_HF1;
				*(u_int8_t *)(packet+i) = *(u_int8_t *)pkt;
				i += 1;
			}
			tcp_hdr_length = ((*(u_int8_t *)pkt) & 0xf0) >> 2;
			pkt += 1;

			/* second header/reserved/flags byte */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_HF2) &&
					(*(u_int8_t *)pkt != *(u_int8_t *)(codec->last_nl_hdr[cid]+13))) {
				nl_hdr_mask2 |= MASK_FLAG_TCP_HF2;
				*(u_int8_t *)(packet+i) = *(u_int8_t *)pkt;
				i += 1;
			}
			pkt += 1;

			/* window size */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_WIN) &&
					(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_nl_hdr[cid]+14))) {
				nl_hdr_mask2 |= MASK_FLAG_TCP_WIN;
				*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
				i += 2;
			}
			pkt += 2;

			/* TCP checksum */
			/* note: TCP and UDP checksum are calculated from an IP pseudo-header, 
			 * the TCP/UDP header, and the TCP/UDP payload
			 * www.liacs.nl/~herbertb/courses/networks/handouts/udp_pseudo.html
			 */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_TCK)) {
				/* XXX: this should be TCP_CHECKSUM */
				UDP_CHECKSUM(ip_hdr, ip_hdr_length, tcp_ck_sum);
				if (*(u_int16_t *)pkt != tcp_ck_sum) {
					nl_hdr_mask2 |= MASK_FLAG_TCP_TCK;
					*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
					i += 2;
				}
			}
			pkt += 2;

			/* urgent pointer (!=0) */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_URG) && (*(u_int16_t *)pkt != 0)) {
				nl_hdr_mask2 |= MASK_FLAG_TCP_URG;
				*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
				i += 2;
			}
			pkt += 2;

			/* options */
			if (ISSET(co->ip_mask, MASK_FLAG_TCP_OPT) &&
					(memcmp (pkt, codec->last_nl_hdr[cid]+20, tcp_hdr_length-20) != 0)) {
				nl_hdr_mask2 |= MASK_FLAG_TCP_OPT;
				bcopy (pkt, (packet+i), tcp_hdr_length-20);
				i += tcp_hdr_length-20;
			}
			pkt += tcp_hdr_length-20;

			/* copy the current network-layer header mask */
			bcopy (nl_hdr, codec->last_nl_hdr[cid], tcp_hdr_length);

			/* copy the second transport-layer header mask */
			packet[ii+1] = nl_hdr_mask2;

			break;


		case IPPROTO_UDP:
			/* compress UDP header */
			nl_hdr_mask = (cid&0x0f)<<4;
			ii = i++;
			if (ip_fragment == 1) {
				/* a packet from a fragmented datagram (except the first fragment)
				 * has no transport-layer header => add only the cid */
				break;
			}
			nl_hdr = (u_char *)pkt;

			/* source port number */
			if (ISSET(co->ip_mask, MASK_FLAG_UDP_USP) &&
					(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_nl_hdr[cid]+0))) {
				nl_hdr_mask |= MASK_FLAG_UDP_USP;
				*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
				i += 2;
			}
			pkt += 2;

			/* destination port number */
			if (ISSET(co->ip_mask, MASK_FLAG_UDP_UDP) &&
					(*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_nl_hdr[cid]+2))) {
				nl_hdr_mask |= MASK_FLAG_UDP_UDP;
				*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
				i += 2;
			}
			pkt += 2;

			/* UDP length */
			if (ISSET(co->ip_mask, MASK_FLAG_UDP_ULN) &&
					(ntohs(*(u_int16_t *)pkt) != (ip_total_length - ip_hdr_length))) {
				nl_hdr_mask |= MASK_FLAG_UDP_ULN;
				*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
				i += 2;
			}
			pkt += 2;

			/* UDP checksum */
			/* note: TCP and UDP checksum are calculated from an IP pseudo-header, 
			 * the TCP/UDP header, and the TCP/UDP payload
			 * www.liacs.nl/~herbertb/courses/networks/handouts/udp_pseudo.html
			 * http://www.netfor2.com/udpsum.htm 
			 */
			if (ISSET(co->ip_mask, MASK_FLAG_UDP_ULN)) {
				UDP_CHECKSUM(ip_hdr, ip_hdr_length, udp_ck_sum);
				if (*(u_int16_t *)pkt != udp_ck_sum) {
					nl_hdr_mask |= MASK_FLAG_UDP_UCK;
					*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
					i += 2;
				}
			}
			pkt += 2;

			/* copy the current network-layer header mask */
			bcopy (nl_hdr, codec->last_nl_hdr[cid], 8);

			break;


		case IPPROTO_ICMP:
			printf ("ICMP: not yet\n");
			break;


		default:
			/* compress network-layer header */
			printf ("Unknown transport protocol: %i\n", transport_protocol);
			break;
	}


	/* copy the transport-layer header mask */
	packet[ii] = nl_hdr_mask;


	/* copy the total number of bytes */
	*(u_int8_t *)(packet+0) = (u_int8_t)i;
	*comp_pkt = packet;
	*comp_len = i;


/* 
	printf ("%i (%i) bytes (cid = %i, %i.%i.%i.%i:%i, %i.%i.%i.%i:%i)\n", i, 
ISSET(nl_hdr_mask2, 0x04) ? (tcp_hdr_length-20) : 0, cid, 
(int)*(ip_hdr+12), (int)*(ip_hdr+13), (int)*(ip_hdr+14), (int)*(ip_hdr+15),
(int)ntohs(*(u_short *)(ip_hdr+ 4 * (int)((*(ip_hdr+0))&0xf) )),
(int)*(ip_hdr+16), (int)*(ip_hdr+17), (int)*(ip_hdr+18), (int)*(ip_hdr+19),
(int)ntohs( *(u_short *)( ip_hdr+2+4*(int)((*(ip_hdr+0))&0xf) ) ));
	printf ("SEQ: %08lx, ACK: %08lx\n", ntohl(*(u_int32_t *)(nl_hdr+4)), ntohl(*(u_int32_t *)(nl_hdr+8)));

	printf ("Packet Compressed: ");
	for (ii=0; ii<i; ii++) {
		printf ("%02x ", *(packet+ii));
	}
	printf ("\n");
*/

	return 0;
}




/*
 * need_restart_markers
 *
 * Description:
 *  - Checks whether paddings, a restart markers, or a codec reinitialization
 *	are needed
 *
 * Inputs:
 *  - co: compression parameters
 *	- fp: lFILE where to write paddings and restart markers
 *	- len: length of the packet to be written
 *	- bytes_written: bytes already written
 *	- codec: codec
 *
 * Outputs:
 *  - result: number of paddings, < 0 if there were problems  
 *
 */
int need_restart_markers (co_t *co, lFILE *fp, int len, 
		u_int32_t bytes_written, codec_t *codec)
{
	int paddings;
	int i;
	u_char comp_pkt;

	paddings = 0;

	/* check if we need to add any paddings */
	if (((bytes_written + len - 1) / co->rm_offset) >
			(bytes_written / co->rm_offset)) {
		comp_pkt = COMPRESSION_PADDING;

		/* get number of paddings */
		paddings = co->rm_offset * ((bytes_written + len - 1) / co->rm_offset) - 
				bytes_written;

		/* write the paddings */
		i = 0;
		while (i < paddings) {
			if (lfwrite (fp, &comp_pkt, 1) < 1) {
				return -1;
			}
			i++;
		}
	}

	/* check if we need to reinit the codec */
	if (((bytes_written + len) / co->rm_offset) >
      (bytes_written / co->rm_offset)) {
		init_codec (codec);
		comp_pkt = COMPRESSION_INIT_CODEC;
		if (lfwrite (fp, &comp_pkt, 1) < 1) {
			return -1;
		}
		paddings++;
	}

	return paddings;
}




/*
 * decode_trace
 *
 * Description:
 *  - Given a codec and a compressed packet, recreates the packet including 
 *		its pcap information. 
 *
 * Inputs:
 *  - codec: codec  
 *  - compressed_buffer: compressed packet
 *
 * Outputs:
 *  - pcap_hdr: packet information (timestamp, caplen, length)
 *  - pkt: pointer to the packet's IP header
 *  - result: bytes written in compressed_buffer if OK, < 0 otherwise  
 *
 */
int decode_trace (codec_t *codec, u_char *compressed_buffer, 
		struct pcap_pkthdr *pcap_hdr, u_char *pkt)
{
	int i;
	int offset, len_offset, ip_cksum_offset, nl_cksum_offset;
	long ts_diff;
	u_int8_t ip_hdr_mask;
	u_char *ip_hdr;
	u_int16_t ip_hdr_length, ip_total_length;
	int ip_fragment;
	int transport_protocol;
	u_int16_t ip_ck_sum;
	int cid;
	u_int8_t nl_hdr_mask;
	u_char *nl_hdr;
	u_int16_t udp_ck_sum;
	u_int8_t nl_hdr_mask2;
	u_int8_t tcp_hdr_length;
	u_int16_t tcp_ck_sum;


	i = 1;
	offset = 0;

	/* recreate pcap header */
	switch (*(u_char *)(compressed_buffer+i)) {
		case 0xff:
			/* 0xff + 8 bytes with full timestamp */
			i++;
			pcap_hdr->ts.tv_sec = ntohl(*(long *)(compressed_buffer+i));
			i += 4;
			pcap_hdr->ts.tv_usec = ntohl(*(long *)(compressed_buffer+i));
			i += 4;
			break;

		case 0xfe:
			/* 0xfe + 2 bytes with unsigned difference */
			i++;
			ts_diff = (long)ntohs(*(u_int16_t *)(compressed_buffer+i));
			i += 2;
			pcap_hdr->ts = ts_add (&(codec->last_pcap_hdr.ts), ts_diff);
			break;

		default:
			/* one byte with unsigned difference */
			ts_diff = (long)(*(u_int8_t *)(compressed_buffer+i));
			pcap_hdr->ts = ts_add (&(codec->last_pcap_hdr.ts), ts_diff);
			i++;
			break;
	}
	*(long *)(pkt+offset) = htonl (pcap_hdr->ts.tv_sec);
	offset += 4;
	*(long *)(pkt+offset) = htonl (pcap_hdr->ts.tv_usec);
	offset += 4;
	len_offset = offset;
	offset += 8;


	/* recreate IP header */
	ip_hdr_mask = *(u_int8_t *)(compressed_buffer+i);
	i++;
	GET_CID(ip_hdr_mask, compressed_buffer+i, cid);
	ip_hdr = pkt+offset;


	/* version, length, and type of service */
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_VLT)) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+0);
	}
	ip_hdr_length = ((*(u_int8_t *)(pkt+offset)) & 0x0f) << 2;
	offset += 2;

	/* total length */
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_LEN)) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+2);
	}
	ip_total_length = ntohs(*(u_int16_t *)(pkt+offset));
	offset += 2;

	/* IP identification */
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_IDN)) {
		if (*(u_int8_t *)(compressed_buffer+i) == 0) {
			i++;
			*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
			i += 2;
		} else {
			*(u_int16_t *)(pkt+offset) = htons(
					ntohs(*(u_int16_t *)(codec->last_ip_hdr[cid]+4)) + 
					(u_int16_t)(*(u_int8_t *)(compressed_buffer+i)));
			i++;
		}
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+4);
	}
	offset += 2;

	/* DF, MF, and fragment offset */
	ip_fragment = 0;
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_FRA)) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+6);
	}
  if ((ntohs(*(u_int16_t *)(pkt+offset)) & 0x1fff) != 0)  {
    /* fragmentation (no first fragment) */
    ip_fragment = 1;
  }
	offset += 2;

	/* TTL and transport protocol */
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_TAP)) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+8);
	}
	transport_protocol = *(u_int8_t *)(pkt+offset+1);
	offset += 2;

	/* checksum */
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_ICK)) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		ip_cksum_offset = offset;
	}
	offset += 2;

	/* source address */
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_SAD)) {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(compressed_buffer+i);
		i += 4;
	} else {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(codec->last_ip_hdr[cid]+12);
	}
	offset += 4;

	/* destination address */
	if (ISSET(ip_hdr_mask, MASK_FLAG_IP_DAD)) {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(compressed_buffer+i);
		i += 4;
	} else {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(codec->last_ip_hdr[cid]+16);
	}
	offset += 4;

	/* IP options */
	if (ip_hdr_length > 20) {
		bcopy (compressed_buffer+i, pkt+offset, ip_hdr_length - 20);
		i += ip_hdr_length - 20;
		offset += ip_hdr_length - 20;
	}

	/* checksum */
	if (!ISSET(ip_hdr_mask, MASK_FLAG_IP_ICK)) {
		IP_CHECKSUM(ip_hdr, ip_hdr_length, ip_ck_sum);
		*(u_int16_t *)(pkt+ip_cksum_offset) = ip_ck_sum;
	}

	bcopy (ip_hdr, codec->last_ip_hdr[cid], ip_hdr_length);


	/* recreate transport-layer header */
	switch (transport_protocol) {

		case IPPROTO_TCP:
			if (ip_fragment == 1) {
				/* a packet from a fragmented datagram (except the first fragment) 
				 * has no transport-layer header => skip it */
				break;
			}

			/* uncompress TCP header */
			nl_hdr_mask = *(u_int8_t *)(compressed_buffer+i);
			i++;
			nl_hdr_mask2 = *(u_int8_t *)(compressed_buffer+i);
			i++;
			nl_hdr = pkt+offset;

			/* source port number */
			if (ISSET(nl_hdr_mask, MASK_FLAG_TCP_TSP)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_nl_hdr[cid]+0);
			}
			offset += 2;

			/* dst port number */
			if (ISSET(nl_hdr_mask, MASK_FLAG_TCP_TDP)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_nl_hdr[cid]+2);
			}
			offset += 2;

			/* sequence number */
			if (ISSET(nl_hdr_mask, MASK_FLAG_TCP_SEQ)) {
				if (*(u_int16_t *)(compressed_buffer+i) == 0) {
					i += 2;
					*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(compressed_buffer+i);
					i += 4;
				} else {
					*(u_int32_t *)(pkt+offset) = htonl(
							ntohl(*(u_int32_t *)(codec->last_nl_hdr[cid]+4)) + 
							(u_int32_t)ntohs(*(u_int16_t *)(compressed_buffer+i)));
					i += 2;
				}
			} else {
				*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(codec->last_nl_hdr[cid]+4);
			}
			offset += 4;

			/* acknowledgment number */
			if (ISSET(nl_hdr_mask, MASK_FLAG_TCP_ACK)) {
				if (*(u_int16_t *)(compressed_buffer+i) == 0) {
					i += 2;
					*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(compressed_buffer+i);
					i += 4;
				} else {
					*(u_int32_t *)(pkt+offset) = htonl(
							ntohl(*(u_int32_t *)(codec->last_nl_hdr[cid]+8)) + 
							(u_int32_t)ntohs(*(u_int16_t *)(compressed_buffer+i)));
					i += 2;
				}
			} else {
				*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(codec->last_nl_hdr[cid]+8);
			}
			offset += 4;

			/* first header/reserved/flags byte */
			if (ISSET(nl_hdr_mask2, MASK_FLAG_TCP_HF1)) {
				*(u_int8_t *)(pkt+offset) = *(u_int8_t *)(compressed_buffer+i);
				i += 1;
			} else {
				*(u_int8_t *)(pkt+offset) = *(u_int8_t *)(codec->last_nl_hdr[cid]+12);
			}
			tcp_hdr_length = ((*(u_int8_t *)(pkt+offset)) & 0xf0) >> 2;
			offset += 1;

			/* second header/reserved/flags byte */
			if (ISSET(nl_hdr_mask2, MASK_FLAG_TCP_HF2)) {
				*(u_int8_t *)(pkt+offset) = *(u_int8_t *)(compressed_buffer+i);
				i += 1;
			} else {
				*(u_int8_t *)(pkt+offset) = *(u_int8_t *)(codec->last_nl_hdr[cid]+13);
			}
			offset += 1;

			/* window size */
			if (ISSET(nl_hdr_mask2, MASK_FLAG_TCP_WIN)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_nl_hdr[cid]+14);
			}
			offset += 2;

			/* TCP checksum */
			if (ISSET(nl_hdr_mask2, MASK_FLAG_TCP_TCK)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				nl_cksum_offset = offset;
			}
			offset += 2;

			/* urgent pointer (!=0) */
			if (ISSET(nl_hdr_mask2, MASK_FLAG_TCP_URG)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				*(u_int16_t *)(pkt+offset) = 0;
			}
			offset += 2;

			/* options */
			if (ISSET(nl_hdr_mask2, MASK_FLAG_TCP_OPT)) {
				bcopy ((compressed_buffer+i), (pkt+offset), tcp_hdr_length-20);
				i += tcp_hdr_length-20;
			} else {
				bcopy ((codec->last_nl_hdr[cid]+20), (pkt+offset), tcp_hdr_length-20);
			}
			offset += tcp_hdr_length-20;

			/* TCP checksum */
			if (!ISSET(nl_hdr_mask2, MASK_FLAG_TCP_TCK)) {
				/* XXX: this should be TCP_CHECKSUM */
				UDP_CHECKSUM(ip_hdr, ip_hdr_length, tcp_ck_sum);
				*(u_int16_t *)(pkt+nl_cksum_offset) = htons(tcp_ck_sum);
			}

			/* copy the current network-layer header mask */
			bcopy (nl_hdr, codec->last_nl_hdr[cid], tcp_hdr_length);

			break;


		case IPPROTO_UDP:
			if (ip_fragment == 1) {
				/* a packet from a fragmented datagram (except the first fragment) 
				 * has no transport-layer header => skip it */
				break;
			}

			/* uncompress UDP header */
			nl_hdr_mask = *(u_int8_t *)(compressed_buffer+i);
			i++;
			nl_hdr = pkt+offset;

			/* source port number */
			if (ISSET(nl_hdr_mask, MASK_FLAG_UDP_USP)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_nl_hdr[cid]+0);
			}
			offset += 2;

			/* destination port number */
			if (ISSET(nl_hdr_mask, MASK_FLAG_UDP_UDP)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_nl_hdr[cid]+2);
			}
			offset += 2;

			/* UDP length */
			if (ISSET(nl_hdr_mask, MASK_FLAG_UDP_ULN)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				*(u_int16_t *)(pkt+offset) = htons((u_int16_t)(ip_total_length - 
						ip_hdr_length));
			}
			offset += 2;

			/* UDP checksum */
			if (ISSET(nl_hdr_mask, MASK_FLAG_UDP_UCK)) {
				*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
				i += 2;
			} else {
				UDP_CHECKSUM(ip_hdr, ip_hdr_length, udp_ck_sum);
				*(u_int16_t *)(pkt+offset) = htons(udp_ck_sum);
			}
			offset += 2;

			bcopy (nl_hdr, codec->last_nl_hdr[cid], 8);
			break;


		case IPPROTO_ICMP:
			printf ("ICMP: not yet\n");
			break;

		default:
			break;
	}

	/* calculate the uncompressed packet length */
	pcap_hdr->caplen = offset - 16;
	pcap_hdr->len = ip_total_length;
	bcopy (pcap_hdr, &codec->last_pcap_hdr, 16);

	*(long *)(pkt+len_offset) = htonl (pcap_hdr->caplen);
	len_offset += 4;
	*(long *)(pkt+len_offset) = htonl (pcap_hdr->len);
	len_offset += 4;

/* 
	printf ("%li.%06li %i.%i.%i.%i:%i > %i.%i.%i.%i:%i  (%i/%i) (cid: %i)\n", 
pcap_hdr->ts.tv_sec, pcap_hdr->ts.tv_usec, 
(int)*(ip_hdr+12), (int)*(ip_hdr+13), (int)*(ip_hdr+14), (int)*(ip_hdr+15),
(int)ntohs(*(u_short *)(ip_hdr+ 4 * (int)((*(ip_hdr+0))&0xf) )),
(int)*(ip_hdr+16), (int)*(ip_hdr+17), (int)*(ip_hdr+18), (int)*(ip_hdr+19),
(int)ntohs( *(u_short *)( ip_hdr+2+4*(int)((*(ip_hdr+0))&0xf) ) ),
pcap_hdr->caplen, pcap_hdr->len, cid);

	printf ("SEQ: %08lx, ACK: %08lx\n", ntohl(*(u_int32_t *)(nl_hdr+4)), ntohl(*(u_int32_t *)(nl_hdr+8)));

	printf ("TCP options: ");
	for (i=0; i<20; i++) {
		printf ("%02x ", *(ip_hdr+20+20+i));
	}
	printf ("\n");

*/

	return offset;
}




/*
 * ts_add
 *
 * Description:
 *  - Adds a timestamp and a value
 *
 * Inputs:
 *  - ts: addend timestamp  
 *  - amount: ammount to be added  
 *
 * Outputs:
 *  - result: resulting timestamp
 *
 */
struct timeval ts_add (const struct timeval *ts, const long amount)
{
	struct timeval res;

	if ((ts->tv_usec + amount) > 1000000) {
		res.tv_sec = ts->tv_sec + 1;
		res.tv_usec = (ts->tv_usec + amount) - 1000000;
	} else {
		res.tv_sec = ts->tv_sec;
		res.tv_usec = (ts->tv_usec + amount);
	}

	return res;
}




/*
 * ts_sub
 *
 * Description:
 *  - Substracts two timestamps, returning the result
 *
 * Inputs:
 *  - tsa: minuend timestamp  
 *  - tsb: subtrahend timestamp  
 *
 * Outputs:
 *  - result: result of the substraction
 *
 */
long ts_sub (const struct timeval *tsa, const struct timeval *tsb)
{
	long diff;

	if ((tsb->tv_sec == 0) && (tsb->tv_usec == 0)) {
		diff = 0x7fffffff;
	} else if (tsa->tv_sec == tsb->tv_sec) {
		diff = tsa->tv_usec - tsb->tv_usec;
	} else {
		diff = 1000000 * (tsa->tv_sec - tsb->tv_sec) +
				(tsa->tv_usec - tsb->tv_usec);
	}
	return diff;
}


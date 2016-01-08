/*
 * wire.h --
 *
 *      pktd daemon: the client stub. The provided API is VP's wire
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


#ifndef _WIRE_H
#define _WIRE_H

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include "protocol.h"
#include "lstdio.h"
#include "trace-codec.h"



/* checkpointing info */
typedef struct {
	int time;
	int length;
	int files;
} cp_t;


#ifndef _PROTOCOL_H
/* compression info */
typedef struct {
	/* trace compression restart marker */
	u_int32_t rm_offset;
	/* trace compression mask */
	u_int8_t ip_mask;
	u_int16_t tcp_mask;
	u_int8_t udp_mask;
} co_t;
#endif


/* connection to the pktd daemon info */
typedef struct {
	/* source of packets we're reading */
	pcap_t *pd;
	int datalink;
	int hdr_size;
	int snaplen;
	int reading_offline;
	struct pcap_stat start_stat; /* 0 */
	pcap_dumper_t *dumper;

	/* the socket to the daemon */
	int datafd;

	/* a lFILE pointer for the local write file */
	lFILE* localfp;

	/* an opaque authentication cookie */
	u_int32_t cookie;

	u_char buffer[MAXDATABUFFER];
	int offset;
	char filter[PROT_MAX_INDIVIDUAL_FILTER];

	/* boolean describing writing mode */
	int mode;

	/* checkpointing info */
	cp_t cp;

	/* trace compression codec */
	codec_t *codec;

	/* trace compression info */
	co_t co;

	/* error code and message */
	int wire_errcode;
} pktd_t;


extern int wire_errcode;


extern char pktd_version[];

/* datalink type to header size */
extern int wire_get_hdr_size (int datalink);

/* initialize a connection to the pktd daemon */
extern pktd_t *wire_init(const char *filter, int snaplen, int mode, cp_t *cp,
		co_t *co, const char *read_file, char *write_file);
/* mode flags */
#define W_DW 0x0001 /* daemon writing */
#define W_LW 0x0002 /* local writing */
#define W_ID 0x0004 /* immediate delivery */
#define W_CO 0x0008 /* packet compression */
#define W_KC 0x0010 /* keep compressed packets */


/* called for each new packet.  Returns number of bytes to save in
 * write_file (if any), counting from the beginning of the IP header.
 * Returning 0 indicates that the packet should not be saved.
 */
typedef int (*wire_callback)(const u_char *pkt, struct timeval ts,
		int len, int caplen, void *user_data);


/* if reading from a save file, then a single call to wire_activity
 * with a nil "fds" goes ahead and calls the callback for each packet
 * in the save file.
 */
extern int wire_activity(pktd_t *pdd, fd_set *fds, wire_callback cb, 
		void *user_data);


/* daemon destroyer */
/* note that from the three statistics returned, 
 *		- ps_recv reports the number of packets received. This includes 
 *		all the packets received at the device, including packets for 
 *		other clients (maybe this is a privacy problem). If you want to 
 *		know how many packets you have received, you can count them
 *		- ps_drop reports the number of packets dropped by the device 
 *		(it's not clear how to account this for every client)
 *		- ps_ifdrop is still unimplemented in most devices, so you better 
 *		forget about it
 */
extern int wire_done(pktd_t *pdd, struct pcap_stat *ps);


/* returns the difference between the packet statistics when 
 * contacting first the daemon and now. 
 * NOTE: experience shows that the interface drop count is 
 * not reliable under FreeBSD
 */
extern int wire_stats(pktd_t *pdd, struct pcap_stat *ps);

/* XXX: number of filter drops since last call (doesn't have sense 
 * here). wire_num_filter_drops is deprecated. Use wire_stats 
 * instead 
 */
extern int wire_num_filter_drops(pktd_t *pdd);

/*
 * requests the daemon to flush the client buffer
 */
extern int wire_flush(pktd_t *pdd);



/* change the filter on-the-fly */
extern int wire_setfilter (pktd_t *pdd, const char *filter, cp_t *cp);


extern int wire_checkpoint (pktd_t *pdd);

extern const char *wire_err_msg(int errcode);

/* packet injection */
extern int wire_inject (pktd_t *pdd, u_char *ip);


extern int wire_max_fd(pktd_t *pdd);
extern int wire_add_fds(pktd_t *pdd, fd_set *fds);
extern int wire_is_set(pktd_t *pdd, fd_set *fds);

#ifdef __cplusplus
}
#endif

#endif


/*
 * daemon.h --
 *
 *  pcap multiplexer daemon: header
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


#ifndef _DAEMON_H
#define _DAEMON_H



#if defined(__linux__)
#include "bpf.h"
#elif (defined(__svr4__) || defined(__SVR4))
#include "bpf.h"
#else
#include <net/bpf.h>
#include <pcap.h>
#endif

#include <semaphore.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>


/* the daemon must have access to the protocol to communicate with clients */
#include "protocol.h"
#include "lstdio.h"
#include "trace-codec.h"


/* simple max/min macros */
#define MAXIMUM(a,b) ((a) > (b) ? (a) : (b))
#define MINIMUM(a,b) ((a) > (b) ? (b) : (a))


/* default values for base directory and file pattern name */
#define DEFAULT_PKTD_BASE_DIRECTORY "/tmp"
#define DEFAULT_PKTD_BASE_FILE_PATTERN "tcpdump-%d.trace"

/* possible states at the Finite State Machine (FSM) that defines 
 * every client (i.e., every pktd_table entry)
 */
typedef enum {
	empty, init, working, filter, checkpoint, closing
} conn_state; 

/* representation of each client */
struct pktd_client_item {
	/* state */
	conn_state state;

	/* filter (text and compiled versions) */
	char filter[PROT_MAX_INDIVIDUAL_FILTER];
	struct bpf_program fp;

	/* index to the device (packet capture descriptor) table */
	int device;

	/* boolean stating whether the daemon must immediately deliver packets 
	 * to the client or its associated file, or if it must cluster them 
	 * before doing the system call to enhance performance */
	int immediate_delivery;

	/* boolean stating whether the client requested compression for its 
	 * traces. Compression reduces the size of the traces, at (let's 
	 * hope marginal) performance cost at the daemon. compression and 
	 * immediate_delivery have no sense at the same time */
	int compression;
	codec_t *codec;
	co_t co;

	/* pattern of the file to dump results to ("" if sending packets to a port) */
	char file_pattern[PROT_MAXFILENAME];

	/* port number of the client (0 if dumping packets to a file) */
	u_int port;

	/* client's file descriptor (may be a file id or a socket id) */
	lFILE *datafp;

	/* snaplen requested by the client */
	u_int snaplen;

	/* an opaque authentication cookie */
	/* XXX: this should definitely be stronger */
	u_int32_t cookie;

	/* time & number of packets limitations */
	struct timeval cp_time;  /* begin time */
	u_int16_t cp_time_max;   /* maximum time in seconds */
	u_int16_t cp_length_max; /* maximum length in KB */
	u_int16_t cp_files;      /* current file being written */
	u_int16_t cp_files_max;  /* maximum number of files */

	/* information about the process that requested the filtering */
	u_int32_t uid;
	u_int32_t gid;
	u_int32_t pid;

	/* bytes written so far */
	u_int32_t bytes_written;

	/* error state */
	int wire_errcode;
};


/* common semaphore (Sys V). If the daemon is compiled with the 
 * shared memory and semaphore option, we use just one old Sys V 
 * semaphore because POSIX 1003.1b semaphores are still unimplemented 
 * in FreeBSD
 */
extern int semaphore;


/* where diagnostic messages should go */
extern FILE *log_file;

/* common error code variable */
extern int wire_errcode;

/* a daemon limitation: max length of a composed filter */
#define PROT_MAX_COMPOSED_FILTER 10240

/* compiled null filter */
#define PKTD_BPF_NULL_FILTER  BPF_STMT(BPF_RET | BPF_K, 0)
#define PKTD_BPF_NULL_FILTER_LEN 1


/* internal daemon's IPC protocol constants when using sockets instead of 
 * shared memory */
#define DAEMON_PROT_MINHEADER  2
#define DAEMON_PROT_REFRESH    (u_int8_t)0x01
#define DAEMON_PROT_EMPTY      (u_int8_t)0x02
#define DAEMON_PROT_DEVICE     (u_int8_t)0x04
#define DAEMON_PROT_STATS      (u_int8_t)0x08
#define DAEMON_PROT_FLUSH      (u_int8_t)0x10


/* the packet capture devices table */
struct pktd_device_item {
	/* source of packets we're reading */
	pcap_t *pd;

	/* the datalink type and the size of the header (DTL_RAW, etc.). 
	 * These values depend only on the interface, so it's the same 
	 * for all entries using the same pcap descriptor. 
	 */
	int datalink;
	int hdr_size;

	/* packet statistics: note that every time pcap_setfilter() is called, 
	 * the kernel call goes to sys/net/bpf.c:bpf_setf() and reset_d(), 
	 * which resets both packet received and packet dropped counts 
	 * (the third statistic, drops by interface, is not yet supported). 
	 * This means we cannot trust the statistics returned by pcap_stats()
	 * unless we account for every time we call pcap_setfilter(). 
	 */

	/* total packet statistics */
	struct pcap_stat total_stat;

	/* last packet statistics */
	struct pcap_stat last_stat;

	/* device filters (text and compiled versions) */
	char filter[PROT_MAX_COMPOSED_FILTER];
	struct bpf_program fcode;

	/* device snaplen */
	u_int snaplen;

	/* netmask used */
	bpf_u_int32 netmask;
};


/* max number of simultaneous clients allowed in the daemon */
#define DAEMON_MAX_CLIENTS 20

/* performance reasons advise not to access the struct pktd_client_item 
 * of each client just to know that it is not working */
conn_state pktd_client_table_state[DAEMON_MAX_CLIENTS];


/* two-device snaplen implementation */
#define DAEMON_NUM_DEVICES 2


/* network and transport protocols: IP + TCP/UDP/ICMP(header). As IP 
 * options are virtually never used, IP = 20. TCP options are more 
 * popular, so we will use TCP/UDP/ICMP(header) = 60. Total = 80
 *
 * NOTE: this should maybe go in protocol.h so that the libwire can 
 * suggest the client to use a better snaplen or at least the latter 
 * can know to which device (slow or fast ones) it will be attached
 */
#define DAEMON_SNAPLEN_FAST_DEVICE 80


/* default kernel filter */
extern const char default_filter[];



/* the low level wire calls */

/* called for each new packet.  Returns number of bytes to save in
 * write_file (if any), counting from the beginning of the IP header.
 * Returning 0 indicates that the packet should not be saved.
 */
typedef int (*_wire_callback)(const u_char *pkt, struct timeval ts,
				int len, int caplen, void *user_data);

extern int _wire_init (int idd, const char *filter, const char *interface,
			u_int snaplen, const char *read_file);

/* experience shows that the interface drop count is not reliable under
 * FreeBSD.
 */
extern int _wire_done (int idd, int *filter_drop_addr, 
		int *interface_drop_addr);

extern int _wire_setfilter (int idd, const char *filter);

extern int _wire_max_fd(int idd);
extern int _wire_set_fds(int idd, fd_set *fds);
extern int _wire_get_fds(int idd);

/* number of filter drops since last call */
extern int _wire_num_filter_drops();

/* if reading from a save file, then a single call to wire_activity
 * with a nil "fds" goes ahead and calls the callback for each packet
 * in the save file.
 */
extern int _wire_activity(fd_set *fds, _wire_callback cb, void *user_data);

#endif


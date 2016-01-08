/*
 * injection.c --
 *
 *	pcap multiplexer daemon: packet injection module
 *
 *	This module carries out, among others, the following abnormalities: 
 *
 *		- access raw sockets
 *		- build link-layer packets (currently just ethernet)
 *		- query the kernel IP-to-MAC cache (currently the ARP cache)
 *		- query the kernel route table
 *
 *	As you can expect, it is heavily dependent on the particular 
 *	machine architecture and OS, so it's highly probable it just 
 *	doesn't work. 
 *
 *	If you want to work without this module (and therefore giving up  
 *	on the daemon injecting packets), modify the Makefile so that the 
 *	two lines that define LIBNET_DEF and LIBNET_LIB get uncommented 
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

/* $Header: /usr/local/share/doc/apache/cvs/pcapd/injection.c,v 1.17 2003/06/21 01:53:43 jyjung Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#if defined(__linux__)
#include <net/if_arp.h>
#include <netinet/ether.h>

#elif (defined(bsdi) || defined(__NetBSD__) || defined(__OpenBSD__) ||\
		defined(__FreeBSD__))
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#elif defined(__sun__)
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(__sun__)
#include <regexpr.h>
#endif
#include <regex.h>

#if (defined(LIBNET_BIG_ENDIAN) || defined(LIBNET_LIL_ENDIAN))
/* __GLIBC__ is needed to avoid libnet/libnet-headers.h redefining 
 * struct ether_addr 
 */
#define __GLIBC__ 1
#include <libnet.h>
#endif

#include "protocol.h"
#include "daemon.h"
#include "injection.h"
#include "log.h"

/* the local ethernet address */
struct ether_addr local_eth;




/*
 * injection_write_ip
 *
 * Description:
 *	- Write an IP packet into the wire. It can use either raw sockets 
 *		or the wire
 *
 * Inputs:
 *	- ip_packet: the IP packet
 *
 * Outputs:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int injection_write_ip (u_char *ip_packet)
{
#if defined(INJECT_USING_RAW_SOCKETS) || defined(INJECT_USING_LINK_LAYER)
	int i;
	u_int16_t packet_size = ntohs(*(u_int16_t*)(ip_packet+2));
#endif


#if defined(INJECT_USING_RAW_SOCKETS)
	int network;

	/* network initialization */
	if ((network = libnet_open_raw_sock(IPPROTO_RAW)) < 0) {
		return WIRE_ERR_PKTD_INJECTION_OPEN;

	/* packet injection */
	} else if ((i = libnet_write_ip (network, ip_packet, packet_size))
			< packet_size) {
		return WIRE_ERR_PKTD_INJECTION_WRITE_IP;

	/* shut down the interface */
	} else if (libnet_close_raw_sock (network) < 0) {
		return WIRE_ERR_PKTD_INJECTION_CLOSE;

	}

	return WIRE_ERR_NONE;

#elif defined(INJECT_USING_LINK_LAYER)

	char buffer[LIBNET_ETH_H+IP_MAXPACKET];
	struct in_addr in;
	int size = 1024;
	struct libnet_link_int *network; /* pointer to link interface struct */
	char *interface = NULL; /* pointer to the device to use */
	struct sockaddr_in sin;
	char errbuf[1024];
	struct ether_addr remote_eth, *tmp_eth;



	/* network initialization */
	if (libnet_select_device(&sin, &interface, errbuf) == -1) {
		return WIRE_ERR_PKTD_NO_WRITE_DEVICE_ACCESS;
	}
	if ((network = libnet_open_link_interface(interface, errbuf)) == NULL) {
 		return WIRE_ERR_PKTD_INJECTION_OPEN;
	}


	/* get local ethernet address */
	if ((tmp_eth = libnet_get_hwaddr(network, interface, errbuf)) == NULL) {
		(void)libnet_close_link_interface(network);
		return WIRE_ERR_PKTD_INJECTION_OPEN;
	}
	memcpy (&local_eth, tmp_eth, 6);

	debug3 ("injection_write_ip: the local ethernet address is %s\n", 
			ether_ntoa(&local_eth));


	/* get remote ethernet address (the packet is already in network order) */
	in.s_addr = *(u_int32_t*)(ip_packet+16);

	/* try to get the remote MAC address from the ARP cache */
	if (get_mac_address (in, buffer, size) < 0) {
		/* MAC address of the IP address not in ARP cache */

		/* get the gateway needed to reach the destination */
		struct in_addr gw;
		if (get_gateway (in, &gw) < 0) {
			debug3 ("injection_write_ip: can't find MAC nor gateway for %s\n", 
					inet_ntoa(in));
			(void)libnet_close_link_interface(network);
			return WIRE_ERR_PKTD_INJECTION_WRITE_IP;
		}

		/* get the gateway's ethernet address */
		if (get_mac_address (gw, buffer, size) < 0) {
			debug3 ("injection_write_ip: can't find MAC for %s's ", 
					inet_ntoa(in));
			debug3 ("gateway (%s)\n", inet_ntoa(gw));
			/* XXX: This case means typically the destination host is in 
			 * the same network than the source, but the destination MAC 
			 * address is not in the local ARP cache. Getting a local 
			 * MAC address requires implementing ARP, which we won't do 
			 * at this moment
			 */
			(void)libnet_close_link_interface(network);
			return WIRE_ERR_PKTD_INJECTION_WRITE_IP;
		}

		debug3 ("injection_write_ip: IP address %s can be reached ", inet_ntoa(in));
		debug3 ("through gateway %s (%s)\n", inet_ntoa(gw), buffer);
	} else {
		debug3 ("injection_write_ip: IP address %s corresponds to %s\n", 
				inet_ntoa(in), buffer);
	}

	if ((tmp_eth = ether_aton (buffer)) == NULL) {
		(void)libnet_close_link_interface(network);
		return WIRE_ERR_PKTD_INJECTION_WRITE_IP;
	}
	memcpy (&remote_eth, tmp_eth, 6);


  /* build ethernet header and use IP packet as payload */
#if (defined(bsdi) || defined(__NetBSD__) || defined(__OpenBSD__) ||\
		defined(__FreeBSD__))
	libnet_build_ethernet(&(remote_eth.octet[0]), 
			&(local_eth.octet[0]), ETHERTYPE_IP, NULL, 0, buffer);
#else
	libnet_build_ethernet(&(remote_eth.ether_addr_octet[0]), 
			&(local_eth.ether_addr_octet[0]), ETHERTYPE_IP, NULL, 0, buffer);
#endif
	memcpy (buffer+LIBNET_ETH_H, ip_packet, packet_size);
	packet_size += LIBNET_ETH_H;


	/* inject the packet */
	if ((i = libnet_write_link_layer (network, interface, buffer,
			packet_size)) < packet_size) {
		(void)libnet_close_link_interface(network);
		return WIRE_ERR_PKTD_INJECTION_WRITE_IP;
	}


	/* shut down the interface */
	(void)libnet_close_link_interface(network);

	return WIRE_ERR_NONE;
#else /* INJECT_USING_LINK_LAYER */
	return(0);
#endif /* INJECT_USING_LINK_LAYER */
}




#if defined(INJECT_USING_LINK_LAYER)
/*
 * get_mac_address
 *
 * Description:
 *	- Translates an IP address to the corresponding MAC address. If 
 *		the address corresponds to a machine outside the local network, 
 *		it returns the MAC address of the next-hop gateway
 *
 * Inputs:
 *	- in: the IP address whose MAC address you want to know 
 *	- mac_address: a buffer to write the corresponding MAC address
 *	- mac_len: the mac_address buffer length
 *
 * Outputs:
 *	- mac_address: the corresponding MAC address
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int get_mac_address (struct in_addr in, u_char *mac_address, int mac_len)
{
	int fd;
	char command[1024];
	char buffer[1024];
	int buf_len = 1024;
	char *tmpfile = "/tmp/xxethernet.tmp";
	char *eth_regexp = "[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+";
	regex_t eth_reg;
	int nmatch = 1;
	regmatch_t pmatch[1];


	/* create a FIFO for the IPC */
#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	if ((mkfifo (tmpfile, FILE_MODE) < 0) && (errno != EEXIST)) {
		return -1;
	}
	if ((fd = open(tmpfile, O_RDONLY | O_NONBLOCK)) < 0) {
		unlink (tmpfile);
		return -1;
	}

	/* query the system ARP cache (see arp(8) manual) */
#if (defined(bsdi) || defined(__NetBSD__) || defined(__OpenBSD__) ||\
		defined(__FreeBSD__))
	sprintf (command, "arp -n %s > %s", inet_ntoa(in), tmpfile);
#elif defined(__linux__)
	sprintf (command, "arp -n -a %s > %s", inet_ntoa(in), tmpfile);
#elif defined(__sun__)
	sprintf (command, "arp %s > %s", inet_ntoa(in), tmpfile);
#endif

	if (injection_system (command) < 0) {
		close (fd);
		unlink (tmpfile);
		return -1;
	}

	/* get the result of the system command */
	if (read (fd, buffer, buf_len) < 0) {
		close (fd);
		unlink (tmpfile);
		return -1;
	}

	/* clean the FIFO socket */
	close (fd);
	unlink (tmpfile);


	/* look for an ethernet address */
	memset(&eth_reg, 0, sizeof(regex_t));
	if (regcomp (&eth_reg, eth_regexp, REG_EXTENDED) < 0) {
		return -1;
	}
	if (regexec (&eth_reg, buffer, nmatch, pmatch, 0) != 0) {
		return -1;
	}

	/* copy the ethernet address to the buffer mac_address */
	strncpy (mac_address, buffer+pmatch[0].rm_so, MINIMUM(mac_len, 
			pmatch[0].rm_eo - pmatch[0].rm_so));
	*(mac_address+MINIMUM(mac_len,pmatch[0].rm_eo - pmatch[0].rm_so)) = '\0';

	debug3 ("get_mac_address: %s (IP) is %s (ethernet)\n", inet_ntoa(in), 
			mac_address);
	return 0;
}




/*
 * get_gateway
 *
 * Description:
 *	- Gets the IP address of the gateway associated to a given IP address 
 *
 * Inputs:
 *	- in: the IP address whose gateway you want to know 
 *
 * Outputs:
 *	- gw: the MAC address corresponding to the gateway
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int get_gateway (struct in_addr in, struct in_addr *gw)
{
	int fd;
	char command[1024];
	char buffer[1024];
	int buf_len = 1024;
	char *tmpfile = "/tmp/xxethernet.tmp";
	int nmatch = 10;
	regmatch_t pmatch[10];

#if (defined(__sun__) ||\
		defined(bsdi) || defined(__NetBSD__) || defined(__OpenBSD__) ||\
		defined(__FreeBSD__))
	char *des_regexp = "destination: ([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*)";
	char *gw_regexp = "gateway: ([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*)";
	regex_t des_reg, gw_reg;

#elif defined(__linux__)
	char *entry_regexp = "([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*) *([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*) *([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*)";
	regex_t entry_reg;
	int buf_index;
	struct in_addr mask, new_dst, new_gw, new_mask;
#endif


	/* create a FIFO for the IPC */
#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	if ((mkfifo (tmpfile, FILE_MODE) < 0) && (errno != EEXIST)) {
		return -1;
	}
	if ((fd = open(tmpfile, O_RDONLY | O_NONBLOCK)) < 0) {
		unlink (tmpfile);
		return -1;
	}


	/* query the system routing cache (see route(8) manual) */
#if (defined(bsdi) || defined(__NetBSD__) || defined(__OpenBSD__) ||\
		defined(__FreeBSD__))
	sprintf (command, "route -n get -inet %s > %s", inet_ntoa(in), tmpfile);
#elif defined(__linux__)
	sprintf (command, "route -n > %s", tmpfile);
#elif defined(__sun__)
	sprintf (command, "route -n get -inet %s > %s", inet_ntoa(in), tmpfile);
#endif
	if (injection_system (command) < 0) {
		close (fd);
		unlink (tmpfile);
		return -1;
	}

	/* get the result of the system command */
	if (read (fd, buffer, buf_len) < 0) {
		close (fd);
		unlink (tmpfile);
		return -1;
	}

	/* clean the FIFO socket */
	close (fd);
	unlink (tmpfile);



#if (defined(__sun__) ||\
		defined(bsdi) || defined(__NetBSD__) || defined(__OpenBSD__) ||\
		defined(__FreeBSD__))

	/* look for a gateway IP address */
	memset(&des_reg, 0, sizeof(regex_t));
	memset(&gw_reg, 0, sizeof(regex_t));
	if (regcomp (&gw_reg, gw_regexp, REG_EXTENDED) < 0) {
		return -1;
	}
	if (regcomp (&des_reg, des_regexp, REG_EXTENDED) < 0) {
		return -1;
	}
	if (regexec (&des_reg, buffer, nmatch, pmatch, 0) != 0) {
		if (regexec (&gw_reg, buffer, nmatch, pmatch, 0) != 0) {
			return -1;
		}
		*(buffer+pmatch[1].rm_eo) = '\0';
		(void)inet_aton (buffer+pmatch[1].rm_so, gw);
	} else {
		*(buffer+pmatch[1].rm_eo) = '\0';
		(void)inet_aton (buffer+pmatch[1].rm_so, gw);
	}
	debug3 ("get_gateway: %s (IP) can be reached through gateway %s\n",
			inet_ntoa(in), inet_ntoa(*gw));

	return 0;


#elif defined(__linux__)

	/* look for a gateway IP address */
	memset(&entry_reg, 0, sizeof(regex_t));
	if (regcomp (&entry_reg, entry_regexp, REG_EXTENDED) < 0) {
		perror ("regcomp");
		exit (1);
	}
	buf_index = 0;
	gw->s_addr = 0;
	mask.s_addr = 0;
	while (regexec (&entry_reg, buffer+buf_index, nmatch, pmatch, 0) == 0) {
		*(buffer+buf_index+pmatch[1].rm_eo) = '\0';
		*(buffer+buf_index+pmatch[2].rm_eo) = '\0';
		*(buffer+buf_index+pmatch[3].rm_eo) = '\0';
		(void)inet_aton (buffer+buf_index+pmatch[1].rm_so, &new_dst);
		(void)inet_aton (buffer+buf_index+pmatch[2].rm_so, &new_gw);
		(void)inet_aton (buffer+buf_index+pmatch[3].rm_so, &new_mask);
		if (((in.s_addr & new_mask.s_addr) == new_dst.s_addr) &&
				(ntohl(new_mask.s_addr) >= ntohl(mask.s_addr))) {
			/* the IP address matches the new destination|mask with bigger mask */
			gw->s_addr = new_gw.s_addr;
			mask.s_addr = new_mask.s_addr;
		}
		buf_index += pmatch[3].rm_eo+1;
	}

	/* check whether there were results */
	if ((gw->s_addr == 0) && (mask.s_addr == 0)) {
		return -1;
	}

	debug3 ("get_gateway: %s (IP) can be reached through gateway %s\n",
			inet_ntoa(in), inet_ntoa(*gw));

	return 0;

#endif

}




/*
 * injection_system
 *
 * Description:
 *	- A wrap to <stdlib.h> system to isolate the caller from SIGCHLD 
 *
 * Inputs:
 *	- cmdstring: the command we want to run in the shell
 *
 * Outputs:
 *	- return: 0 if ok, <0 if there were problems
 *
 * More:
 *	- the problem that requires wrapping the system call is that calling 
 *	system() raises a SIGCHLD signal when the child forked by system() 
 *	dies. Stevens ([Ste93], pp. 310-315) suggests blocking SIGCHLD while 
 *	executing the command, and unblocking it just before returning control 
 *	to the caller. 
 *
 *	The problem is that when the forked child exits, it raises SIGCHLD. 
 *	The parent (the system() call itself) is indeed vwait'ing for it, 
 *	which gets rid of the state associated with the child - and therefore 
 *	avoids the child's turning into a zombie. But the parent doesn't 
 *	catch the signal. Just after SIGCHLD is unblocked before system() 
 *	returns, the signal raises and the caller's handler is dispatched. 
 *
 *	Moreover, this signal cannot be dealt with by vwait'ing it because 
 *	it has been already vwait'ed. If the caller tries to vwait this 
 *	SIGCHLD (typical approach to this signal), it gets a "No child 
 *	processes" error message. 
 *
 *	We checked that just before undoing the SIGCHLD block, the pending 
 *	signal mask is 0x80000. 
 *
 *	The solution for now will be to ignore SIGCHLD while running 
 *	system(). In other words, if one of the caller's children dies 
 *	while it's into injection_system, it'll never know and its 
 *	children will wander dead for centuries. 
 *
 *
 * [Ste93] "Advanced Programming in the Unix Environment", by W. Richard 
 * 	Stevens
 */
int injection_system (const char *cmdstring)
{
	int res;
	struct sigaction ignore, savechld;

	/* ignore SIGCHLD */
	ignore.sa_handler = SIG_IGN;
	sigemptyset(&ignore.sa_mask);
	ignore.sa_flags = 0;
	if (sigaction(SIGCHLD, &ignore, &savechld) < 0)
		return(-1);

	res = system(cmdstring);

	/* undo SIGCHLD ignoring */
	if (sigaction(SIGCHLD, &savechld, NULL) < 0)
		return(-1);

	return res;
}


#endif /* INJECT_USING_LINK_LAYER */


#
# Makefile --
#
#       This is the makefile for pktd and libwire.
#
# Copyright (c) 1993-2002 The International Computer Science Institute.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# A. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# B. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# C. Neither the names of the copyright holders nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
# OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# - pktd is the daemon
# - libwire is the library clients use
# - client contains several example clients
# - pktzip is a trace compressor/uncompressor
ALL = pktd client

# XXX: get the OS
#OS:sh =uname -s
#REV: sh =uname -r
#OS= $(shell uname -s)
#REV= $(shell uname -r)
#
#OS = `uname -s`
#REV = `uname -r`
#
#test:
#	@echo Compiling for $(OS) $(REV)
#	ifeq ($(OS), FreeBSD)
#	@echo "this is freebsd"
#	endif


# compiler 
CC = gcc

# uncomment these two lines to run purify on Solaris
#CC = purify gcc
#CCOPT = -g


#	compile debug options
#CCOPT = -g -Wall -pedantic -O -funroll-loops
CCOPT = -I/usr/include/pcap -I. -g -Wall -pedantic
#CCOPT = -O3 -Wall


# Compile Options:

#	- add -DIPC_USING_SOCKETS to use sockets as IPC means between 
#	the smgr and the fmgr. Add -DIPC_USING_SHMEM_SEM to use shared 
#	memory and semaphores
IPC_TYPE = -DIPC_USING_SOCKETS
#IPC_TYPE = -DIPC_USING_SHMEM_SEM

# - you may need to change this to something else, like 
#	../libpcap-<version>, if you're linking to a special libpcap version.
PCAP_LIB = -L/usr/local/lib -lpcap

# - uncomment the following lines to use libnet for packet injection
#CCOPT := $(CCOPT) -DINJECT_USING_RAW_SOCKETS
#CCOPT := $(CCOPT) -DINJECT_USING_LINK_LAYER
#LIBNET_DEF = `libnet-config --defines`
#LIBNET_LIB = `libnet-config --libs`





CFLAGS = $(CCOPT) $(IPC_TYPE) $(LIBNET_DEF)
LDFLAGS = -L. -llstdio $(PCAP_LIB) $(LIBNET_LIB)

# if OS == SunOS
# uncomment the following line to compile on Solaris
#LDFLAGS :=  $(LDFLAGS) -lsocket -lnsl -lresolv
# endif


all: $(ALL)

OBJS = wire.o daemon.o protocol.o client.o pktzip.o log.o
SRC = $(OBJS:.o=.c)

protocol.o: protocol.h protocol.c
	$(CC) $(CFLAGS) -c protocol.c

log.o: log.h log.c
	$(CC) $(CFLAGS) -c log.c

trace-codec.o: trace-codec.h trace-codec.c
	$(CC) $(CFLAGS) -c trace-codec.c -o trace-codec.o

lstdio.o: lstdio.h lstdio.c
	$(CC) $(CFLAGS) -c lstdio.c -o lstdio.o
	ar cr liblstdio.a lstdio.o


pktd: protocol.o log.o injection.o lstdio.o trace-codec.o daemon.h daemon.c
	$(CC) $(CFLAGS) -O -funroll-loops -c daemon.c
	$(CC) $(CFLAGS) -O -funroll-loops -o $@ daemon.o protocol.o log.o injection.o trace-codec.o $(LDFLAGS)


libwire: protocol.o trace-codec.o
	$(CC) $(CFLAGS) -c -O wire.c
	# uncomment the following line to compile on FreeBSD/Linux
	ar cr $@.a wire.o protocol.o trace-codec.o
	# uncomment the following line to compile on Solaris (dynamic libraries)
	#gcc -G -o $@.so wire.o protocol.o $(LDFLAGS)


client: client.c libwire
	# uncomment the following line to compile on FreeBSD/Linux
	$(CC) $(CFLAGS) -o $@ $@.c libwire.a $(LDFLAGS)
	# uncomment the following line to compile on Solaris (dynamic libraries)
	#gcc -G $(CFLAGS) -o $@ $@.c $(LDFLAGS)


pktzip: libwire protocol.o
	# uncomment the following line to compile on FreeBSD/Linux
	$(CC) $(CFLAGS) -o $@ $@.c protocol.o libwire.a $(LDFLAGS)
	# uncomment the following line to compile on Solaris (dynamic libraries)
	#gcc -G $(CFLAGS) -o $@ $@.c protocol.o $(LDFLAGS)


injection:
	$(CC) $(CFLAGS) -c $@.c



tar:
	$(MAKE) TARBALL=pktd-`grep "pktd_version" version.h | sed -e 's/char pktd_version\[\] = "//' | sed -e 's/";//'` tarball


tarball:
	rm -f $(TARBALL) $(TARBALL).tar.gz
	echo $(TARBALL)
	ln -s . $(TARBALL)
	tar cf $(TARBALL).tar \
		$(TARBALL)/*.c \
		$(TARBALL)/*.h \
		$(TARBALL)/CHANGES.html \
		$(TARBALL)/Makefile \
		$(TARBALL)/README \
		$(TARBALL)/TODO
	gzip $(TARBALL).tar
	rm -f $(TARBALL)

clean:
	rm -f $(OBJS) pktd daemon.o protocol.o client wire.o injection.o log.o\
		trace-codec.o pktzip.o pktzip libwire.a libwire.so lstdio.o\
		liblstdio.a core


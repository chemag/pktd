pktd: A Packet Capture and Injection Daemon
-------------------------------------------

Copyright (c) 2001 - 2002 The International Computer Science Institute

Copyright (c) 2002 - 2002 Lawrence Berkeley National Laboratory

Copyright (c) 2002 - 2016 Jose Maria Gonzalez (chema@cs.berkeley.edu)




# Abstract

pktd is a packet capture and injection multiplexer daemon that provides
controlled, fine-grained access to the network device. On systems running
pktd, client measurement tools are not given direct access to the
network device. Instead, they are obliged to request access via pktd.
By providing administrators control over the pktd mechanism, they
can easily and securely enforce their desired policies concerning
which clients should be granted which sorts of network access
capabilities. Thus, pktd can serve as the sole trusted, privileged
entity for conducting measurements, eliminating the need for
administrators to vet the individual measurement tool

The PAM 2003 (Proceedings of the 4th International workshop on Passive
and Active network Measurement, PAM 2003) paper is available
[here](http://github.com/chemag/pktd/blob/master/doc/gonzalez_and_paxson.pktd_a_packet_capture_and_injection_daemon.pdf).


# Introduction

One of the objectives of the
[NIMI measurement platform](https://www.caida.org/research/performance/measinfra/evaldetail.xml#nimi)
is to provide 
a secure environment where measurement applications with different 
trust levels run. In order to achieve this, we have created pktd, 
a multiplexer daemon over the standard, packet capture library used 
to access network devices (libpcap). 


Access policies in current packet capture libraries are too coarse for 
our objective of providing different measurement rights. For example, 
Solaris and BPF-based architectures - most BSD Operating Systems - 
implement network device access rights based on classic owner/group/other 
read/write access associated to a file - in this case a virtual device, 
called `/dev/bpf%x` in BSD. If a client has read access to this device, 
she can add any filter she wishes, including promiscuous-mode ones. 
There is no way of implementing fine-grained policies, as allowing 
her to access only to the IP and TCP headers of all traffic in a 
given port. Other operating systems provide even coarser access 
policies. For example, in Linux, clients that want to access the 
network device have to be root or setuid. 


Some operating systems present further limitations in the access to the 
network device. BPF-based devices only permit one process listening 
to each `/dev/bpf%x` virtual device, which effectively impedes a large 
number of measurement clients trying to work at the same time. 


As a part of the NIMI research effort, we have written pktd, a general 
capture/injection packet daemon to whom clients request measurements. 
pktd is a single trusted, privileged entity in the full measurement 
system. Clients have to request measurements to pktd, which in turn 
decides whether granting access depending in the measurement box 
owner's policy. 


We think it makes sense for the owner of the measurement box to 
implement complex access privileges depending on the identity of 
the client and the filter she requests. For example, one client 
may be allowed to query the ssh port (where all sensitive data 
is encrypted), but not the telnet one (where passwords go in the 
clear). A second restriction may come from the amount of data a 
client is allowed to snap. We could ensure a client monitoring 
http performance never accesses sensitive http contents by 
limiting the maximum number of captured bytes to the sum of the 
IP and TCP header. 


A third type of limitations is based on the server managing client's 
access to trace contents. For example, traffic traces may be 
anonymized before being served to an untrustworthy client. Finally, 
in order to avoid hogging of platform resources, the server may 
restrict the amount of traffic (number of packets or number of 
bytes) a client snaps.


Our goal is therefore to provide a secure-access mechanism 
to the libpcap library. On top of this mechanism, the owner 
of the measurement box implements his own trust and 
performance-based policies. 


The solution we propose is to add in measurement machines a libpcap 
multiplexer daemon (pktd) with full access to the packet capture 
interface. This daemon also attends clients on a well-known port at 
the loopback interface. When a client process wants to carry out a 
measurement, it contacts the daemon with a measurement request and 
some identification information. Depending on this information, 
the daemon decides whether allowing the measurement. If the request 
is accepted, the daemon itself carries out the measurement, 
forwarding the data to the client. 


The daemon may also be used to record traffic for off-line analysis. For 
that purpose, we have included the possibility of a client requesting 
the daemon to write traffic to a disk file, instead of the sending
it to the client over the connection between them. In this case, and 
as the traffic may grow with no limit, the daemon supports 
checkpointing, meaning that it generates new files for each stream 
it's recording to disk, and closes the old ones. 


It is important to remark that for clients, the method to request a 
measurement is the one used in accessing directly to libpcap, i.e., 
a BPF-complaining filter. We have created a library (libwire) that 
clients use to request measurements to the daemon using the same 
libpcap interface. 


It is essential to some measurements to have active access to the 
network device. While some software packages try to standardize 
writing access to the network device, we want again to provide 
fine-grained policy decisions to the box owner. For example, 
it may be OK for a client to inject a well-formed ICMP packet 
addressed to a computer whose distance to the measurement box 
is being calculated. On the other hand, full writing access to 
the network device is a capability few system owners are willing 
to permit. 


We have added an injection module to pktd. Currently, the daemon 
decides in a per-packet and per-user basis. A client willing to 
send a packet from the daemon builds and forwards it to the 
daemon, which decides if injecting it to the network. 



# Architecture

The pktd multiplexer daemon is composed of two different systems: 

1. The first is a daemon that serves a well-known port, and provides 
policy-controlled access to the libpcap packet capture device and a 
packet injection system. The daemon is actually composed of two 
processes: a filter manager ("fmgr"), which serves the libpcap 
device, and the socket manager ("smgr"), which attends and processes 
the client's requests, including packet injection requests. 

fmgr and the smgr exchange data in one of the following two 
different ways:

  * through a mmap'ed table (pktd_table) synchronized with semaphores. 
  You have to compile the code with the flag -DIPC_USING_SHMEM_SEM

  * using loopback-interface sockets. You have to compile the code with 
  the flag -DIPC_USING_SOCKETS 


2. The second system is a library - libwire - which you link with 
your client. This library provides access to the daemon instead of 
hooking directly to the libpcap packet device. An example of a 
client that access the daemon through libwire is provided (client.c). 
The interface provided by the libwire library is very similar to 
VP's wire library. 




# Notes on running the code

## Requisites

In order to compile and run pktd (aka pcapd), you need:

* gcc, but not the infamous (gcc-2.96 version)[http://gcc.gnu.org/gcc-2.96.html]
  See http://www.faqs.org/faqs/C-faq/faq/ section 15.10
* read access to the packet filter device. This means read access to 
  `/dev/bpfx` in BSD, read access to `/dev/hme` in Solaris, and being 
  root in Linux,
* libpcap 0.5 or newer (www.tcpdump.org.), 
* libnet 1.0.2a or newer (www.packetfactory.net./Projects/Libnet), in 
  case you want to use the packet injection feature. In this case 
  you also need root privileges on Solaris. 


## Compiling

The software works currently (2002) in Linux, FreeBSD, and Solaris. To make 
the system work, unzip and untar in a directory, modify the Makefile 
at your will and then "make all". With the current Makefile you 
should get two executables, called "pktd" and "client", and a 
library (static libwire.a for FreeBSD and Linux, and dynamic libwire.so 
in Solaris). "pktd" is the daemon and "client" the result of 
compiling the example code (client.c) and linking it with libwire. 


## Operation

If you have problems while running the code, compile it with the 
-DDEBUG flag and write me back with the terminal output,
attaching as much information about the experiment conditions as possible.


After compiling the code, run the daemon. It needs root (or setuid) 
access in the following cases: 

* on Linux
* on Solaris if you want to use the injection module
* on FreeBSD if you want to use the injection module by accessing 
  the raw socket interface (there's the possibility of injecting 
  packets by writing directly on the link-layer device, which 
  doesn't require root access)

You can check the daemon options bu running "pktd --help". Once the 
daemon is running, start as many clients as you want. 


The client executable lets you choose if the results are to be dumped 
to a file (FILE case) or received through a socket (SOCKET case), in 
which case they're are printed in a tcpdump fashion. In the FILE 
case ("client -f"), the client exits immediately, and the daemon 
keeps dumping packets to a file. The name of this file is a default 
one unless you request a name pattern. Such name pattern is a normal 
file name with the characters "%d" in the middle. For example, if 
you want your dump files to be named "icmp-0.trace", "icmp-1.trace", 
and so on, you should use the following command: 

```
client -f "icmp-%d.trace"
```

The name cannot include any slashes to avoid misbehaving clients 
fiddling with directories. 

In the SOCKET case (typing "client -p"), the client prints all the 
packets that is receiving in a tcpdump fashion. It waits until it 
receives 5 packets. Then, it requests the injection of an ICMP 
packet and a filter change. After 5 more packets are received, the 
client exits. 


The daemon detects clients that die and erase them from the table of 
clients. 


Code still unimplemented or doubtful is marked with the initials XXX. 
Grepping for these initials you can get an idea of what's needed. 


# Explanation about the files included

* daemon files
  * src/daemon.h: daemon header
  * src/daemon.c: daemon implementation
  * src/bpf_filter.c: slightly-modified version of BPF bpf_filter.c file
  * src/bpf.h: slightly-modified version of BPF main header (net/bpf.h)
  * src/mbuf.h: bpf requires the memory buffer heading file, which doesn't 
    exist out of BSD
  * src/injection.h: injection module header
  * src/injection.c: injection module implementation

* client stub files
  * src/wire.h: these are the header and the implementation of the wire stub. 
  * src/wire.c: The interface is pretty much VP's one, with some needed 
        modifications added

* client file
  * src/client.c: this is an example of how to use the library

* common files
  * src/version.h: header containing the package version number
  * src/protocol.h: header of the the protocol between clients and the daemon
  * src/protocol.c: implementation of the protocol between clients and the 
            daemon. 

* src/Makefile: should work in FreeBSD and Linux (at least)

* notes files
  * README.md: this file
  * src/TODO: a list of things that should be done


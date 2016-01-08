/*
 * daemon.c --
 *
 *	pcap multiplexer daemon: socket manager (smgr) and filter manager (fmgr)
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


#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <regex.h>

#include <sys/ioctl.h>

#if defined(__sun__)
#include "bpf.h"
#else
#include <net/bpf.h>
#include <pcap.h>
#endif

#include <pcap-int.h>

#include "daemon.h"
#include "protocol.h"
#include "version.h"
#include "log.h"
#include "lstdio.h"

#if (defined(LIBNET_BIG_ENDIAN) || defined(LIBNET_LIL_ENDIAN))
#include "injection.h"
#endif


extern char pcap_version[];
extern char pktd_version[];

/* <errno.h>::errno global variable */
extern int errno;

#if defined(__sun__)
extern char *sys_errlist[];
#endif


/* ensure one and only one IPC method */
#ifndef IPC_USING_SHMEM_SEM
#ifndef IPC_USING_SOCKETS
/* if nothing has been requested, choose one IPC */
#define IPC_USING_SHMEM_SEM
#endif
#endif

#ifdef IPC_USING_SHMEM_SEM
#ifdef IPC_USING_SOCKETS
/* if both have been requested, choose only one IPC */
#undef IPC_USING_SOCKETS
#endif
#endif


/* NOTE: null_filter is the filter that is installed when no client 
 * has requested a particular filter. The filter should be such that 
 * it's never matched by any packet. 
 *
 * The right solution would be to uninstall the filter when no client 
 * has a request, but for now an impossible filter would do it. The 
 * current one is not completely impossible, but it doesn't matter too 
 * much if eventually a packet matches it because the second filtering 
 * (the user one, based on the real filters requested by clients) 
 * stops packets from being delivered to any client.
 *
 * We cannot install an impossible filter (like "tcp and udp") because 
 * pcap's pcap_compile refuses to accept it. An alternative may be to 
 * create our own "filter impossible" instead of getting it by compiling 
 * (we should already know enough about BPF).
 *
 * A third alternative consists of using an impossible filter that is more 
 * subtle than the previous one and therefore can pass the compilation and 
 * installation process. This installation process checks the code root not 
 * to be null and different from BPF_RET or BPF_K. I'm not sure anyway 
 * that this worths too much.
 *
 * The right solution was suggested by Honza Pomahac and Guy Harris in 
 * the tcpdump-workers mailing list on 07/11/2002. pcap_compile fails 
 * with filter expressions rejecting all packets, so the idea is to 
 * create a "ret #0" compiled filter ourselves. 
 *
 * http://www.tcpdump.org/lists/workers/2002/07/msg00052.html
 *
 * We'll keep using the null_filter filter expression to avoid writing 
 * a parallel API using compiled filters instead of filter expressions. 
 * set_pcap_filter, the procedure that indeed compiles the filter 
 * expression, will check for the null_filter expression, and in that 
 * case it will create a "ret #0" compiled filter. 
 *
 */
const char null_filter[1024] = "null_filter";


/* socket where the daemon listens for clients */
int main_socket;

/* the clients table */
struct pktd_client_item *pktd_client_table;

/* the devices table */
struct pktd_device_item *pktd_device_table;


#ifdef IPC_USING_SOCKETS
/* socket where both daemon processes communicate (id and port) */
int ipc_socket;
u_int ipc_port;
#endif

#ifdef IPC_USING_SHMEM_SEM
/* semaphore used to regulate access to the common table */
int semaphore = -1;

#if (defined(__linux__) || defined(__sun__))
/* file descriptor for the file mapped to the memory */
int shmem_client_fd = -1;
int shmem_device_fd = -1;
#endif
#endif


/* pids for the smgr and fmgr processes so they can kill each other
 * (not very constructive purpose, isn't it?)
 */
pid_t pktd_pid[2];
#define SMGR_PID 0
#define FMGR_PID 1


/* variable used to ensure organized death of the two processes that 
 * compose the daemon
 */
int pktd_kill_done = 0;


/* some PCAP-access variables */
static int reading_offline = 0;


/* packet injection */
int packet_injection_allowed = 0;


/* fork into daemon mode */
int fork_into_daemon_mode = 1;



/*
 * declaration of default base directory and pattern
 * both variables can be modified using command-line options
 */
char pktd_base_directory[PROT_MAXFILENAME] = DEFAULT_PKTD_BASE_DIRECTORY;
char pktd_base_file_pattern[PROT_MAXFILENAME] = DEFAULT_PKTD_BASE_FILE_PATTERN;


/* network device interface */
char* pktd_interface = NULL;

/* flag indicating whether debug mode is on (set on the command line) */
int debug_flag = 0;

/* log level */
LogLevel log_level = SYSLOG_LEVEL_INFO;



/* declaration of some functions and procedures */
void pktd_usage (char **argv);
int pktd_parse_args (int argc, char **argv);
int pktd_get_directory (char *string, char* dirname);
int pktd_daemonize ();
pid_t pktd_detach (void (*funp) (void *), void *argv);
int pktd_init_common (struct pktd_client_item **pktd_client_tablep, 
		struct pktd_device_item **pktd_device_tablep);
void pktd_smgr_main (void *argv);
void pktd_fmgr_main (void *argv);
void pktd_signal_handler (int signum);
void pktd_special_signal_handler (int signum);
void pktd_client_table_change ();
void pktd_exit (int code);
void pktd_printf_client_table (struct pktd_client_item *pktd_client_table);
static void pktd_callback (u_char *user, const struct pcap_pkthdr *hdr,
		const u_char *pkt);
int pktd_match (struct bpf_program fp, const u_char *pkt, u_int len, 
		u_int caplen);
int pktd_compile_filter (char *filter, u_int snaplen, int datalink, 
		struct bpf_program *fp);
void pktd_empty_entry (int idc);
void pktd_get_stats (int idd, struct pcap_stat *stat);
#ifdef IPC_USING_SOCKETS
void pktd_refresh_client_table (int idc);
void pktd_report_device_info (int idd);
int pktd_serve_fmgr (int fd);
int pktd_serve_smgr (int fd);
#endif
int pktd_serve_client (int fd);
int pktd_get_filename (const char *pattern, int number, char *filename);
int pktd_get_device (u_int snaplen);
int pktd_free_entry ();
int pktd_cookie2index (u_int32_t cookie);
u_int32_t pktd_filter_permission (u_int32_t uid, u_int32_t gid, u_int32_t pid, 
		char *filter, u_int snaplen, int idc);
int pktd_write_permission (u_char *ip, int idc);
int pktd_do_checkpoint (int idc);
int pktd_mark_checkpoint (int idc);
void pktd_install_signal_handlers ();

/* some useful lower-level code */
static int set_pcap_filter (int idd, const char *filter);
static pcap_t *open_pcap_file (int idd, const char *read_file);
static pcap_t *open_pcap_interface (int idd, const char *interface);

#ifdef IPC_USING_SHMEM_SEM
/* declaration of semaphore functions and procedures */
static int seminit ();
static void sempost (int sem_id);
#ifdef NODEF
static int semtrywait (int sem_id);
#endif
static void semwait (int sem_id);
static int semdestroy (int sem_id);
#endif



/*
 * main
 *
 * Description:
 *	- The main daemon procedure. Forks off the fmgr as a child and converts 
 *		itself into the smgr
 *
 * Inputs:
 *	- argc: argument counter  
 *	- argv: arguments
 *
 */
int main(int argc, char *argv[])
{
	/* parse the argument line */
	if (pktd_parse_args (argc, argv) < 0) {
		exit(1);
	}


	/* initialize log output */
	/* stderr is not a constant expression (glibc-faq 3.9) */
	log_init(argv[0], log_level == -1 ? SYSLOG_LEVEL_INFO : log_level,
			SYSLOG_FACILITY_USER, stderr, fork_into_daemon_mode);

	debug1 ("Daemon will write in %s\n", pktd_base_directory);


	if (fork_into_daemon_mode) {
		/* convert pktd to a daemon */
		if (pktd_daemonize () < 0) {
			exit(1);
		}
	}


	/* do the common initialization */
	if (pktd_init_common (&pktd_client_table, &pktd_device_table) < 0) {
		pktd_exit(1);
	}


	/* detach the fmgr process as a child. The parent will implement the smgr */
	if ((pktd_pid[FMGR_PID] = pktd_detach (pktd_fmgr_main, NULL)) < 0) {
		pktd_exit(1);
	}
	pktd_smgr_main (NULL);
	return 0;
}




/*
 * pktd_usage
 *
 * Description:
 *	- A usage method
 *
 * Inputs:
 *	- argv: arguments
 *
 * Outputs:
 *
 */
void pktd_usage(char **argv)
{
	fprintf (stderr, "Usage: %s [options]\n", *argv);
	fprintf (stderr, "  -h\t\t\tShow this information\n");
	fprintf (stderr, "  -V\t\t\tDisplay version number only\n");
	fprintf (stderr, "  -w directory\t\tSet directory to write traces [%s]\n",
			DEFAULT_PKTD_BASE_DIRECTORY);
	fprintf (stderr, "  -F file_pattern\tSet the default file pattern [%s]\n",
			DEFAULT_PKTD_BASE_FILE_PATTERN);
	fprintf (stderr, "  -I\t\t\tPacket injection allowed\n");
	fprintf (stderr, "  -i interface\t\tListen on interface\n");
	fprintf (stderr, "  -d\t\t\tDebugging mode (multiple -d means more debugging)\n");
	fprintf (stderr, "  -D\t\t\tDo not fork into daemon mode\n");
	return;
}




/*
 * pktd_parse_args
 *
 * Description:
 *	- Parse command line for options
 *
 * Inputs:
 *	- argc: argument counter  
 *	- argv: arguments
 *
 * Outputs:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_parse_args (int argc, char **argv)
{
	int arg;
	extern char *optarg;
	extern int optind;
	extern int opterr;
	int result;

	/* the arguments to options must be separated by white-space */
	opterr = 0;
	while ((arg = getopt(argc, argv, "w:F:Ii:DdVh?")) != -1) {
		switch (arg) {
			case 'w':
				/* new base directory requested */
				result = pktd_get_directory (optarg, pktd_base_directory);
				if (result == -1) {
					fprintf (stderr, "Error getting current directory\n");
					return -1;
				} else if (result == -2) {
					fprintf (stderr, "Error: directory %s doesn't exist\n", 
							pktd_base_directory);
					return -1;
				} else if (result == -3) {
					fprintf (stderr, "Error: %s is not a valid directory\n", 
							pktd_base_directory);
					return -1;
				} else if (result == -4) {
					fprintf (stderr, "Error: cannot write in %s\n", 
							pktd_base_directory);
					return -1;
				}
				break;

			case 'F':
				/* new default filename pattern requested */
				strcpy (pktd_base_file_pattern, optarg);
				break;


			case 'I':
				/* packet injection allowed */
				packet_injection_allowed = 1;
#if (!defined(LIBNET_BIG_ENDIAN) && !defined(LIBNET_LIL_ENDIAN))
				fprintf (stderr, "Cannot inject packets (need LIBNET library)\n");
				return -1;
#endif
				break;

			case 'i':
				/* specific network interface requested */
				pktd_interface = optarg;
				/* strcpy (pktd_interface, argv[optind]); */
				break;


			case 'D':
				fork_into_daemon_mode = 0;
				break;


			case 'd':
				if (debug_flag == 0) {
					debug_flag = 1;
					log_level = SYSLOG_LEVEL_DEBUG1;
				} else if (log_level < SYSLOG_LEVEL_DEBUG3) {
					log_level++;
				} else {
					error ("Too high debugging level");
				}
				break;

			case 'V':
				/* dump version number and exit */
				fprintf (stderr, "pktd %s\n", pktd_version);
				fprintf (stderr, "libpcap %s\n", pcap_version);
				exit(0);
				break;

			case 'h':
			case '?':
			default:
				pktd_usage(argv);
				return -1;
				break;
    }
  }

	return 0;
}




/*
 * pktd_get_directory
 *
 * Description:
 *	- Gets the working directory
 *
 * Inputs:
 *	- string: string supplied by the user  
 *
 * Outputs:
 *	- dirname: final directory name
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_get_directory (char *string, char* dirname)
{
	struct stat st;
	char current_directory[2048];
	char filename[2048];
	int fd;

	if (string[0] == '/') {
		/* absolute directory */
		strcpy (dirname, string);
	} else {
		/* relative directory */
		if (getcwd (current_directory, 2048) == NULL) {
			return -1;
		}
		sprintf (dirname, "%s/%s", current_directory, string);
	}

	/* check the new directory exists */
	if (stat (dirname, &st) < 0) {
		return -2;
	}
	if (!S_ISDIR (st.st_mode)) {
		return -3;
	}

	/* check we can write on it */
	sprintf (filename, "%s/%s", dirname, ".pktd_deleteme");
	if ((fd = open (filename, O_WRONLY|O_CREAT|O_TRUNC, 
        S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
		return -4;
	}
	close (fd);
	unlink (filename);

	return 0;
}




/*
 * pktd_daemonize
 *
 * Description:
 *	- Daemon-izes pktd. It detaches the main process from the current 
 *		terminal process group and makes it a child of init. It also 
 *		closes all the associated terminals and gets a correct directory 
 *		and file mask. 
 *
 * Output:
 *	- return: 0 if ok, <0 if there were problems
 *
 *	Code obtained from http://www2.linuxjournal.com/lj-issues/issue47/2335.html
 *
 */
int pktd_daemonize ()
{
	struct rlimit res_limit = {0, 0};
	int i;
	int fd = -1;

	/* fork once so that the child process is not a process group leader 
	 * and therefore can setsid to a new session and group
	 */
	switch (fork()) {
		case -1:
			perror ("fork()");
			return -1;
		case 0:
			/* child process */
			break;
		default:
			/* parent process */
			exit (0);
	}

	/* close all the process' open file descriptors */
	res_limit.rlim_max = 0;
	if (getrlimit (RLIMIT_NOFILE, &res_limit) < 0) {
		/* this shouldn't happen */
		perror ("getrlimit()");
		return -1;
	}

	if (res_limit.rlim_max == 0) {
		perror ("Max number of open file descriptors is 0!!\n");
		return -1;
	}

	/* for any unknown reason, closing already invalid file descriptors 
	 * triggers an EBADF error at the again2 label. We know no 
	 * descriptors have been open apart from the three inherited from the 
	 * shell (stdin, stdout, and stderr), so therefore we just need close 
	 * 0, 1, and 2
	 * 
	for (i = 0; i < res_limit.rlim_max; i++) {
	 * 
	 */
	for (i = 0; i < 3; i++) {
		(void) close(i);
	}

	/* creates a new session and group */
	if (setsid () < 0) {
		error ("setsid(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}

	/* fork again so that the child obtains a process group id equal to zero */
	switch (fork()) {
		case -1:
			error ("fork(): %s (%d)\n", sys_errlist[errno], errno);
			return -1;
		case 0:
			/* (second) child process */
			break;
		default:
			/* parent process */
			exit(0);
	}

	/* change the working directory and the file mask */
	chdir ("/");
	umask (0);

	/* open the new stdin, stdout, and stderr */
	if ((fd = open ("/dev/null", O_RDWR)) < 0) {
		error ("open(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	};
	if (dup (fd) < 0) {
		error ("dup(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}
	if (dup (fd) < 0) {
		error ("dup(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}

	return 0;
}



/*
 * pktd_init_common
 *
 * Description:
 *	- Does some common initialization before detaching any children. It 
 *		includes getting the parent pid, installing common signal handlers, 
 *		creating and resetting pktd_client_table and pktd_device_table. 
 *		Should we use shared memory, it also mmaps both tables and creates 
 *		the semaphore to synchronize access to the first one
 *
 * Inputs:
 *	- pktd_client_tablep: a pointer to the common, clients table
 *	- pktd_device_tablep: a pointer to the common, devices table
 *
 * Output:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_init_common (struct pktd_client_item **pktd_client_tablep, 
		struct pktd_device_item **pktd_device_tablep)
{
	int idc, idd;
#ifdef IPC_USING_SHMEM_SEM
#if (defined(__linux__) || defined(__sun__))
	struct pktd_client_item tmp_client_item;
	struct pktd_device_item tmp_device_item;
#endif
#endif

	/* parent initialization */
	pktd_pid[SMGR_PID] = getpid();
	pktd_pid[FMGR_PID] = 0;

	/* signal handlers */
	pktd_install_signal_handlers();


#ifdef IPC_USING_SOCKETS
	/* open the IPC socket */
	ipc_port = 0;
	if ((ipc_socket = pktd_server_socket (&ipc_port)) < 0) {
		error ("Cannot open internal socket (%s)\n", wire_err_msg());
		pktd_exit(1);
	}

	/* create the clients table (later forking will create different copies) */
	if ((*pktd_client_tablep = (struct pktd_client_item *)calloc 
			(DAEMON_MAX_CLIENTS, sizeof(struct pktd_client_item))) == 0) {
		error ("calloc(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}

	/* create the devices table (later forking will create different copies) */
	if ((*pktd_device_tablep = (struct pktd_device_item *)calloc 
			(DAEMON_NUM_DEVICES, sizeof(struct pktd_device_item))) == 0) {
		error ("calloc(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}
#endif


#ifdef IPC_USING_SHMEM_SEM
	/* create the semaphore to synchronize access to the common, clients table */
	if ((semaphore = seminit()) < 0) {
		return -1;
	}

	/* create the common clients table (mmap it) */

	/* The map code comes from "Unix Networking Programming," vol. 2, 
	 * 2nd edition, by W.R. Stevens ( http://www.kohala.com/start/ )
	 */

#if (defined(bsdi) || defined(__NetBSD__) || defined(__OpenBSD__) ||\
		defined(__FreeBSD__))
	/* map the shared memory structures */
	if ((*pktd_client_tablep = (struct pktd_client_item *)mmap (NULL, 
			DAEMON_MAX_CLIENTS * sizeof(struct pktd_client_item), PROT_READ | 
			PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED) {
		error ("mmap(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}

	if ((*pktd_device_tablep = (struct pktd_device_item *)mmap (NULL, 
			DAEMON_NUM_DEVICES * sizeof(struct pktd_device_item), PROT_READ | 
			PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED) {
		error ("mmap(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}


#elif (defined(__linux__) || defined(__sun__))
#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
	if ((shmem_client_fd = open("/tmp/zero", O_RDWR | O_CREAT, FILE_MODE)) < 0) {
		error ("open(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	};
	if ((shmem_device_fd = open("/tmp/one", O_RDWR | O_CREAT, FILE_MODE)) < 0) {
		error ("open(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	};

	/* initialize the tmp_xxx_item structures */
	bzero ((void *)&tmp_client_item, sizeof(struct pktd_client_item));
	bzero ((void *)&tmp_device_item, sizeof(struct pktd_device_item));

	/* write pktd_client_table and pktd_device_table to the file */
	for (idc = 0; idc < DAEMON_MAX_CLIENTS; idc++) {
		write(shmem_client_fd, &tmp_client_item, sizeof(struct pktd_client_item));
	}
	for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
		write(shmem_device_fd, &tmp_device_item, sizeof(struct pktd_device_item));
	}

	/* map the file to the shared memory structures */
	if ((*pktd_client_tablep = (struct pktd_client_item *) mmap (NULL, 
			DAEMON_MAX_CLIENTS * sizeof(struct pktd_client_item), PROT_READ | 
			PROT_WRITE, MAP_SHARED, shmem_client_fd, 0)) == MAP_FAILED) {
		error ("mmap(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}
	if ((*pktd_device_tablep = (struct pktd_device_item *) mmap (NULL, 
			DAEMON_NUM_DEVICES * sizeof(struct pktd_device_item), PROT_READ | 
			PROT_WRITE, MAP_SHARED, shmem_device_fd, 0)) == MAP_FAILED) {
		error ("mmap(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}
#endif
#endif

	/* reset the clients table */
	for (idc = 0; idc < DAEMON_MAX_CLIENTS; idc++) {
		memset ((*pktd_client_tablep)+idc, 0, sizeof(struct pktd_client_item));
		((*pktd_client_tablep)+idc)->state = empty;
		pktd_client_table_state[idc] = empty;
		((*pktd_client_tablep)+idc)->datafp = NULL;
	}

	/* reset the devices table */
	for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
		/* as the pd pointer only has sense in the fmgr, we'll use a negative 
		 * datalink as a mark meaning that a device hasn't been open */ 
		((*pktd_device_tablep)+idd)->pd = NULL;
		((*pktd_device_tablep)+idd)->datalink = -1;
	}

	return 0;
}



/*
 * pktd_printf_client_table
 *
 * Description:
 *	- Printf's the common, client table for logging and debugging purposes
 *
 * Inputs:
 *	- pktd_client_table: the table to be printed
 *
 */
void pktd_printf_client_table (struct pktd_client_item *pktd_client_table)
{
	int idc;

	for (idc = 0; idc < DAEMON_MAX_CLIENTS; idc++) {
		if ((pktd_client_table+idc)->state != empty) {
			verbose ("\tpktd_client_table[%i]: state=%i, filter=\"%s\",\
					snaplen=%i device=%i", idc, 
					(pktd_client_table+idc)->state, (pktd_client_table+idc)->filter, 
					(pktd_client_table+idc)->snaplen, (pktd_client_table+idc)->device);
		}
	}

	return;
}




/*
 * pktd_empty_entry
 *
 * Description:
 *	- In case it's needed, report the smgr that an entry was emptied 
 *		so that it can update its copy of the pktd_client_table. 
 *
 * Inputs:
 *	- idc: the client table entry to empty
 *
 */
void pktd_empty_entry (int idc)
{
#ifdef IPC_USING_SOCKETS
	u_char buffer[1024];
	int nbytes;

	/* write the message to the smgr */
	buffer[0] = DAEMON_PROT_EMPTY;
	buffer[1] = (u_char)idc;

	/* send the message */
	if ((nbytes = write (ipc_socket, buffer, DAEMON_PROT_MINHEADER)) < 0) {
		/* error while writing the message: the socket is dead */
		error ("write(internal socket): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}
#endif

	return;
}




/*
 * pktd_refresh_client_table
 *
 * Description:
 *	- Report the fmgr about the new entry values so that it can change 
 *		the filter entry
 *
 * Inputs:
 *	- idc: the client table entry to refresh
 *
 */
void pktd_refresh_client_table (int idc)
{
#ifdef IPC_USING_SOCKETS
	u_char buffer[1024];
	int nbytes;

	/* write the message to the fmgr */

	/* create the message header and send it */
	buffer[0] = DAEMON_PROT_REFRESH;
	buffer[1] = (u_char)(idc & 0xff);
	if ((nbytes = write (ipc_socket, buffer, DAEMON_PROT_MINHEADER)) < 0) {
		/* error while writing the message: the socket is dead */
		error ("write(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}

	/* marshall and send the pktd_client_item */

	/* NOTE: this marshalling won't work when the machine that marshalls 
	 * and the one that unmarshalls use different endianism. This is not
	 * a problem because the smgr and the fmgr run in the same box,
	 * though.
	 */
	if ((nbytes = write (ipc_socket, (u_char *)(pktd_client_table+idc), 
			sizeof(struct pktd_client_item))) < 0) {
		/* error while writing the message: the socket is dead */
		error ("write(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}
#endif

#ifdef IPC_USING_SHMEM_SEM
	/* send a SIGUSR signal to the fmgr so that it changes the filter */
	kill (pktd_pid[FMGR_PID], SIGUSR1);
#endif

	return;
}




/*
 * pktd_get_stats
 *
 * Description:
 *	- Report device packet statistics
 *
 * Inputs:
 *	- idd: the device table entry to refresh
 *
 * Output:
 *	- stat: device packet statistics
 *
 */
void pktd_get_stats (int idd, struct pcap_stat *stat)
{

#ifdef IPC_USING_SOCKETS
	if (getpid() != pktd_pid[SMGR_PID]) {
		/* the filter manager has always access to the pcap_t structure */
#endif

	if (strcmp ((pktd_device_table+idd)->filter, null_filter) != 0) {
		if (pcap_stats((pktd_device_table+idd)->pd, stat) < 0) {
			stat->ps_recv = 0;
			stat->ps_drop = 0;
			stat->ps_ifdrop = 0;
		}
	} else {
		stat->ps_recv = 0;
		stat->ps_drop = 0;
		stat->ps_ifdrop = 0;
	}

	/* add total_stat */
	stat->ps_recv += (pktd_device_table+idd)->total_stat.ps_recv;
	stat->ps_drop += (pktd_device_table+idd)->total_stat.ps_drop;
	stat->ps_ifdrop += (pktd_device_table+idd)->total_stat.ps_ifdrop;

	/* substact last_stat */
	stat->ps_recv -= (pktd_device_table+idd)->last_stat.ps_recv;
	stat->ps_drop -= (pktd_device_table+idd)->last_stat.ps_drop;
	stat->ps_ifdrop -= (pktd_device_table+idd)->last_stat.ps_ifdrop;



#ifdef IPC_USING_SOCKETS
	} else {
		/* only the fmgr has access to the pcap_t structure */
		u_char buffer[1024];
		int nbytes;
		fd_set fds;
		int result;
		int nfds;

		/* write a request message to the fmgr */

		/* create the message header and send it */
		buffer[0] = DAEMON_PROT_STATS;
		buffer[1] = (u_char)(idd & 0xff);
		if ((nbytes = write (ipc_socket, buffer, DAEMON_PROT_MINHEADER)) < 0) {
			/* error while writing the message: the socket is dead */
			error ("write(): %s (%d)\n", sys_errlist[errno], errno);
			pktd_exit(1);
		}

		/* select the socket */
		FD_ZERO (&fds);
		FD_SET (ipc_socket, &fds);
		nfds = getdtablesize();
		if ((result = select (nfds, &fds, NULL, NULL, NULL)) < 0) {
			error ("parent - error during select");
			exit (1);
		}

		/* when there's a message from the fmgr process, serve it */
		if (FD_ISSET (ipc_socket, &fds)) {
			/* message from the filter process */
			(void)pktd_serve_fmgr (ipc_socket);
		}

		/* copy results to the total_stat variable */
		*stat = (pktd_device_table+idd)->total_stat;
	}

#endif

	return;
}




/*
 * pktd_flush_client
 *
 * Description:
 *	- Flushes client socket
 *
 * Inputs:
 *	- idc: the client table entry to flush
 *
 * Output:
 *
 */
void pktd_flush_client (int idc)
{

#ifdef IPC_USING_SHMEM_SEM
	lfflush ((pktd_client_table+idc)->datafp);

#else
	u_char buffer[1024];
	int nbytes;

	/* write the message to the fmgr */

	/* create the message header and send it */
	buffer[0] = DAEMON_PROT_FLUSH;
	buffer[1] = (u_char)(idc & 0xff);
	if ((nbytes = write (ipc_socket, buffer, DAEMON_PROT_MINHEADER)) < 0) {
		/* error while writing the message: the socket is dead */
		error ("write(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}

#endif

	return;
}




#ifdef IPC_USING_SOCKETS
/*
 * pktd_report_device_info
 *
 * Description:
 *	- Sends a message to the smgr reporting the hdr_size
 *
 * Inputs:
 *	- idd: device identifier (pktd_device_table entry)
 *	- datalink: datalink type
 *	- hdr_size: header size
 *	- snaplen: device capture length
 *
 */
void pktd_report_device_info (int idd)
{
	u_char buffer[1024];
	int nbytes;

	/* write the message to the smgr */
	buffer[0] = DAEMON_PROT_DEVICE;
	buffer[1] = (u_char)(idd & 0xff);
	if ((nbytes = write (ipc_socket, buffer, DAEMON_PROT_MINHEADER)) < 0) {
		/* error while writing the message: the socket is dead */
		error ("write(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}

	/* marshall and send the pktd_device_item */

	/* NOTE: this marshalling won't work when the machine that marshalls 
	 * and the one that unmarshalls use different endianism. This is not
	 * a problem because the smgr and the fmgr run in the same box,
	 * though.
	 */
	if ((nbytes = write (ipc_socket, (u_char *)(pktd_device_table+idd), 
			sizeof(struct pktd_device_item))) < 0) {
		/* error while writing the message: the socket is dead */
		error ("write(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}

	return;
}




/*
 * pktd_serve_fmgr
 *
 * Description:
 *	- Attends the fmgr, which is communicating through the IPC socket 
 *		(fd). Attending the fmgr implies listening to its message and 
 *		modifying the pktd_client_table in an approriate way.
 *
 *		Currently we support two different messages from the fmgr to 
 *		the smgr:
 *
 *			message     direction    meaning
 *			-------     ---------    -------
 *			EMPTY       fmgr->smgr   the fmgr has emptied an entry in the 
 *			                         client table
 *			                         data socket
 *			DEVICE      fmgr->smgr   reports device information (the packet 
 *			                         datalink type (datalink), header size 
 *			                         (hdr_size), and snaplen (snaplen) values
 *			STATS       fmgr->smgr   reports packet statistics information 
 *			                         for a device
 *
 *		The receiver never answers.
 *
 * Inputs:
 *	- fd: the filter socket descriptor
 *
 * Output:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_serve_fmgr (int fd)
{
	int nbytes;
	char buffer[1024];
	int idc, idd;
	struct pktd_device_item tmp_item;
	struct pcap_stat tmp_stat;
	u_char *tmpp;

	/* get the minimum header */
again1:
	if ((nbytes = read (fd, buffer, DAEMON_PROT_MINHEADER)) < 
			DAEMON_PROT_MINHEADER) {
		if (errno == EINTR) {
			goto again1;
		}
		error ("read(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}

	switch (buffer[0]) {
		case DAEMON_PROT_EMPTY:
			/* message "empty entry" (idc) */
			idc = (u_int)buffer[1];
			(pktd_client_table+idc)->state = empty;
			pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
			break;

		case DAEMON_PROT_DEVICE:
			/* message "set device info" (idd, datalink, hdr_size, snaplen) */
			idd = (int)buffer[1];

			/* receive and unmarshall the pktd_device_item */
			nbytes = 0;
			tmpp = (u_char *)(&tmp_item);
again2:
			if ((nbytes += read (fd, tmpp, sizeof(struct pktd_device_item))) < 
					sizeof(struct pktd_device_item)) {
				if ((errno == 0) || (errno == EINTR)) {
					tmpp += nbytes;
					goto again2;
				}
				error ("read(): %s (%d)\n", sys_errlist[errno], errno);
				pktd_exit(1);
			}

			(pktd_device_table+idd)->datalink = tmp_item.datalink;
			(pktd_device_table+idd)->hdr_size = tmp_item.hdr_size;
			(pktd_device_table+idd)->snaplen = tmp_item.snaplen;
			break;

		case DAEMON_PROT_STATS:
			/* message "stats are" (idd, stat) */
			idd = (int)buffer[1];

			/* receive and unmarshall the pcap_stat */
			nbytes = 0;
			tmpp = (u_char *)(&tmp_stat);
again3:
			if ((nbytes += read (fd, tmpp, sizeof(struct pcap_stat))) < 
					sizeof(struct pcap_stat)) {
				if ((errno == 0) || (errno == EINTR)) {
					tmpp += nbytes;
					goto again3;
				}
				error ("read(): %s (%d)\n", sys_errlist[errno], errno);
				pktd_exit(1);
			}
			(pktd_device_table+idd)->total_stat = tmp_stat;
			break;
	}

	return 0;
}
#endif




/*
 * pktd_serve_smgr
 *
 * Description:
 *	- Attends the smgr, which is communicating through the IPC socket 
 *		(fd).
 *
 *		Currently we support one different message from the smgr 
 *		to the fmgr:
 *
 *			message     direction    meaning
 *			-------     ---------    -------
 *			REFRESH     smgr->fmgr   the smgr has modified an entry in the 
 *			                         pktd_client_table
 *			STATS       smgr->fmgr   requests packet statistics information 
 *			                         for a device
 *			FLUSH       smgr->fmgr   requests client buffer flushing
 *
 *		The receiver only answers in the STATS case.
 *
 * Inputs:
 *	- fd: the filter socket descriptor
 *
 * Output:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_serve_smgr (int fd)
{
	int nbytes;
	char buffer[1024];
	int idc, idd;
	u_char *tmpp;
	struct pcap_stat stat;
	struct pktd_client_item tmp_item;

	/* get the minimum header */
again4:
	if ((nbytes = read (fd, buffer, DAEMON_PROT_MINHEADER)) < 
			DAEMON_PROT_MINHEADER) {
		if (errno == EINTR) {
			goto again4;
		}
		error ("read(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit(1);
	}

	switch (buffer[0]) {
		case DAEMON_PROT_STATS:
			/* message "get stats" (idd) */
			idd = (u_int)buffer[1];

			/* get statistics */
			pktd_get_stats (idd, &stat);

			/* answer to the smgr */
			buffer[0] = DAEMON_PROT_STATS;
			buffer[1] = (u_char)(idd & 0xff);
			if ((nbytes = write (fd, buffer, DAEMON_PROT_MINHEADER)) < 0) {
				/* error while writing the message: the socket is dead */
				error ("write(): %s (%d)\n", sys_errlist[errno], errno);
				pktd_exit(1);
			}

			/* marshall and send the struct pcap_stat */
			/* NOTE: this marshalling won't work when the machine that marshalls 
			 * and the one that unmarshalls use different endianism. This is not
			 * a problem because the smgr and the fmgr run in the same box,
			 * though */
			if ((nbytes = write (fd, (u_char *)&stat, 
					sizeof(struct pcap_stat))) < 0) {
				/* error while writing the message: the socket is dead */
				error ("write(): %s (%d)\n", sys_errlist[errno], errno);
				pktd_exit(1);
			}
			break;

		case DAEMON_PROT_REFRESH:
			/* message "refresh table entry" (idc) */
			idc = (u_int)buffer[1];

			/* receive and unmarshall the pktd_client_item */
			nbytes = 0;
			tmpp = (u_char *)(&tmp_item);
again5:
			if ((nbytes += read (fd, tmpp, sizeof(struct pktd_client_item))) < 
					sizeof(struct pktd_client_item)) {
				if ((errno == 0) || (errno == EINTR)) {
					tmpp += nbytes;
					goto again5;
				}
				error ("read(): %s (%d)\n", sys_errlist[errno], errno);
				pktd_exit(1);
			}

			/* do a table_change */
			(pktd_client_table+idc)->state = tmp_item.state;
			pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
			strcpy ((pktd_client_table+idc)->filter, tmp_item.filter);
			(pktd_client_table+idc)->device = tmp_item.device;
			(pktd_client_table+idc)->immediate_delivery = 
					tmp_item.immediate_delivery;
			(pktd_client_table+idc)->compression = tmp_item.compression;
			if ((pktd_client_table+idc)->compression == 1) {
				(pktd_client_table+idc)->codec = create_codec ();
			} else {
				(pktd_client_table+idc)->codec = NULL;
			}
			strcpy ((pktd_client_table+idc)->file_pattern, tmp_item.file_pattern);
			(pktd_client_table+idc)->port = tmp_item.port;
			(pktd_client_table+idc)->snaplen = tmp_item.snaplen;
			(pktd_client_table+idc)->cookie = tmp_item.cookie;

			if (tmp_item.state == init) {
				(pktd_client_table+idc)->cp_time = tmp_item.cp_time;
				(pktd_client_table+idc)->cp_time_max = tmp_item.cp_time_max;
				(pktd_client_table+idc)->cp_length_max = tmp_item.cp_length_max;
				(pktd_client_table+idc)->cp_files= tmp_item.cp_files;
				(pktd_client_table+idc)->cp_files_max = tmp_item.cp_files_max;
				(pktd_client_table+idc)->bytes_written = 0;
			}

			(pktd_client_table+idc)->uid = tmp_item.uid;
			(pktd_client_table+idc)->gid = tmp_item.gid;
			(pktd_client_table+idc)->pid = tmp_item.pid;

			(pktd_client_table+idc)->co.rm_offset = tmp_item.co.rm_offset;
			(pktd_client_table+idc)->co.ip_mask = tmp_item.co.ip_mask;
			(pktd_client_table+idc)->co.tcp_mask = tmp_item.co.tcp_mask;
			(pktd_client_table+idc)->co.udp_mask = tmp_item.co.udp_mask;

			pktd_client_table_change();
			break;

		case DAEMON_PROT_FLUSH:
			/* message "flush client buffer" (idc) */
			idc = (u_int)buffer[1];
idd = (pktd_client_table+idc)->device;
/*
// YYY
if (ioctl((pktd_device_table+idd)->pd->fd, BIOCFLUSH, (void *)0 ) < 0) {
error("ioctl: BIOCFLUSH");
abort();
}
*/
			lfflush ((pktd_client_table+idc)->datafp);
			break;
	}

	return 0;
}




/*
 * pktd_serve_client
 *
 * Description:
 *	- Attends the client that is communicating through the fd socket 
 *		descriptor. Attending a client implies listening its message, 
 *		modifying the pktd_client_table in a proper way, and answering 
 *		back. It is important to realize that this procedure doesn't
 *		modify any of the main pktd_client_table fields because that 
 *		responsability is exclusively owned by the fmgr process. 
 *		Therefore, the smgr process just adds the arguments (i.e., the 
 *		less-important pktd_client_table fields) and then signals it 
 *		to the fmgr
 *
 * Inputs:
 *	- fd: the client socket descriptor
 *
 * Output:
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_serve_client (int fd)
{
	int request, command, status;
	u_int32_t cookie = 0;
#if (defined(LIBNET_BIG_ENDIAN) || defined(LIBNET_LIL_ENDIAN))
	int i;
#endif
	int idc;
	int idd;
	int device;
	char filename[PROT_MAXFILENAME];
	int table_refresh_needed = 0;
	struct pcap_stat stat;


	/* get the control message */
	if (pktd_recv (fd, &request, &command, &status) < 0) {
		log ("error getting message from client (%s)\n", wire_err_msg());
		return -1;
	}

	/* check that the packet is a request */
	if (!request) {
		/* the client sent an answer! */
		wire_errcode = WIRE_ERR_PROT_BAD_FORMED_REQUEST;
		return -1;
	}

	switch (command) {
		case PROT_TYPE_WIRE_INIT_P:
			wire_errcode = WIRE_ERR_NONE;

			/* check there are free entries */
			if ((idc = pktd_free_entry()) < 0) {
				wire_errcode = WIRE_ERR_PKTD_TOO_MANY_CLIENTS;

			/* check the client has permission to use the filter */
			} else if ((cookie = pktd_filter_permission (pktd_prot_uid, 
					pktd_prot_gid, pktd_prot_pid, pktd_prot_filter, 
					pktd_prot_snaplen, idc)) <= 0) {
				wire_errcode = WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_FILTER;

			/* check there's at least an open valid device */
			} else if ((device = pktd_get_device (pktd_prot_snaplen)) < 0) {
				wire_errcode = WIRE_ERR_PKTD_NO_DEVICE;

			} else {
#ifdef IPC_USING_SHMEM_SEM
				semwait(semaphore);
#endif
				(pktd_client_table+idc)->state = init;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
				(pktd_client_table+idc)->cookie = cookie;
				strcpy ((pktd_client_table+idc)->filter, pktd_prot_filter);
				(pktd_client_table+idc)->immediate_delivery = 
						pktd_prot_immediate_delivery;
				(pktd_client_table+idc)->compression = pktd_prot_compression;
				(pktd_client_table+idc)->port = pktd_prot_port;
				(pktd_client_table+idc)->file_pattern[0] = '\0';
				(pktd_client_table+idc)->snaplen = pktd_prot_snaplen;
				(pktd_client_table+idc)->device = device;
				(pktd_client_table+idc)->cp_time.tv_sec = 0L;
				(pktd_client_table+idc)->cp_time.tv_usec = 0L;
				(pktd_client_table+idc)->cp_time_max = 0;
				(pktd_client_table+idc)->cp_length_max = 0;
				(pktd_client_table+idc)->cp_files = 0;
				(pktd_client_table+idc)->cp_files_max = 0;
				(pktd_client_table+idc)->uid = pktd_prot_uid;
				(pktd_client_table+idc)->gid = pktd_prot_gid;
				(pktd_client_table+idc)->pid = pktd_prot_pid;
				(pktd_client_table+idc)->co.rm_offset = pktd_prot_co_rm_offset;
				(pktd_client_table+idc)->co.ip_mask = pktd_prot_co_ip_mask;
				(pktd_client_table+idc)->co.tcp_mask = pktd_prot_co_tcp_mask;
				(pktd_client_table+idc)->co.udp_mask = pktd_prot_co_udp_mask;
#ifdef IPC_USING_SHMEM_SEM
				sempost(semaphore);
#endif
			}

			/* send the answer */
			idd = (pktd_client_table+idc)->device;
			pktd_get_stats (idd, &stat);
			if (wire_errcode == WIRE_ERR_NONE) {
				if (pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode, cookie, 
						((pktd_client_table+idc)->compression) ? DLT_RAW : 
						(pktd_device_table+idd)->datalink,
						((pktd_client_table+idc)->compression) ? 0 : 
						(pktd_device_table+idd)->hdr_size,
						stat.ps_recv, stat.ps_drop, stat.ps_ifdrop) < 0) {
					wire_errcode = WIRE_ERR_PROT_SENDING_DATA;
				}
			} else {
				pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode);
			}

			if (wire_errcode != WIRE_ERR_NONE) {
#ifdef IPC_USING_SHMEM_SEM
				semwait(semaphore);
#endif
				(pktd_client_table+idc)->state = empty;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
				(pktd_client_table+idc)->port = 0;
#ifdef IPC_USING_SHMEM_SEM
				sempost(semaphore);
#endif
				return -1;
			}

			table_refresh_needed = 1;
			break;


		case PROT_TYPE_WIRE_INIT_F:
			wire_errcode = WIRE_ERR_NONE;

			/* check there are free entries */
			if ((idc = pktd_free_entry()) < 0) {
				wire_errcode = WIRE_ERR_PKTD_TOO_MANY_CLIENTS;

			/* check the client has permission to use the filter */
			} else if ((cookie = pktd_filter_permission (pktd_prot_uid, 
					pktd_prot_gid, pktd_prot_pid, pktd_prot_filter, 
					pktd_prot_snaplen, idc)) <= 0) {
				wire_errcode = WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_FILTER;

			/* check that the pattern is allowed */
			} else if (pktd_get_filename (pktd_prot_file_pattern, 0, 
					filename) < 0) {
				wire_errcode = WIRE_ERR_PROT_ILLEGAL_PATTERN;

			/* check there's at least an open valid device */
			} else if ((device = pktd_get_device (pktd_prot_snaplen)) < 0) {
				wire_errcode = WIRE_ERR_PKTD_NO_DEVICE;

			} else {
#ifdef IPC_USING_SHMEM_SEM
				semwait(semaphore);
#endif
				(pktd_client_table+idc)->state = init;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
				(pktd_client_table+idc)->cookie = cookie;
				strcpy ((pktd_client_table+idc)->filter, pktd_prot_filter);
				(pktd_client_table+idc)->immediate_delivery = 
						pktd_prot_immediate_delivery;
				(pktd_client_table+idc)->compression = pktd_prot_compression;
				if (pktd_prot_file_pattern[0] != '\0') {
					strcpy ((pktd_client_table+idc)->file_pattern, 
					pktd_prot_file_pattern);
				} else {
					strcpy ((pktd_client_table+idc)->file_pattern, 
					pktd_base_file_pattern);
				}
				(pktd_client_table+idc)->snaplen = pktd_prot_snaplen;
				(pktd_client_table+idc)->device = pktd_get_device 
						((pktd_client_table+idc)->snaplen);
				(void) gettimeofday(&((pktd_client_table+idc)->cp_time), NULL);
				(pktd_client_table+idc)->cp_time_max = pktd_prot_cp_time;
				(pktd_client_table+idc)->cp_length_max = pktd_prot_cp_length;
				(pktd_client_table+idc)->cp_files= 0;
				(pktd_client_table+idc)->cp_files_max = pktd_prot_cp_files;
				(pktd_client_table+idc)->uid = pktd_prot_uid;
				(pktd_client_table+idc)->gid = pktd_prot_gid;
				(pktd_client_table+idc)->pid = pktd_prot_pid;
				(pktd_client_table+idc)->co.rm_offset = pktd_prot_co_rm_offset;
				(pktd_client_table+idc)->co.ip_mask = pktd_prot_co_ip_mask;
				(pktd_client_table+idc)->co.tcp_mask = pktd_prot_co_tcp_mask;
				(pktd_client_table+idc)->co.udp_mask = pktd_prot_co_udp_mask;
#ifdef IPC_USING_SHMEM_SEM
				sempost(semaphore);
#endif
			}

			/* send the answer */
			if (wire_errcode == WIRE_ERR_NONE) {
				if (pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode, 
						cookie, filename) < 0) {
					wire_errcode = WIRE_ERR_PROT_SENDING_DATA;
				}
			} else {
				pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode);
			}

			if (wire_errcode != WIRE_ERR_NONE) {
#ifdef IPC_USING_SHMEM_SEM
				semwait(semaphore);
#endif
				(pktd_client_table+idc)->state = empty;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
				(pktd_client_table+idc)->port = 0;
#ifdef IPC_USING_SHMEM_SEM
				sempost(semaphore);
#endif
				return -1;
			}

			table_refresh_needed = 1;
			break;


		case PROT_TYPE_WIRE_SETFILTER:
			wire_errcode = WIRE_ERR_NONE;

			/* check the client has already registered */
#ifdef IPC_USING_SHMEM_SEM
			semwait(semaphore);
#endif
			idc = pktd_cookie2index (pktd_prot_cookie);
#ifdef IPC_USING_SHMEM_SEM
			sempost(semaphore);
#endif

			if (idc <= 0) {
				wire_errcode = WIRE_ERR_PKTD_BAD_COOKIE;

			/* check the client has permission to use the filter */
			} else if (pktd_filter_permission ((pktd_client_table+idc)->uid, 
					(pktd_client_table+idc)->gid, (pktd_client_table+idc)->pid, 
					pktd_prot_filter, pktd_prot_snaplen, idc) <= 0) {
				/* XXX: this should be protected by semaphores */
				wire_errcode = WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_FILTER;
			}

			/* send the answer */
			if (wire_errcode == WIRE_ERR_NONE) {
				if (pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode) < 0) {
					/* if we can't write to the control socket, just forget the request */
					return -1;
				}
			} else {
				pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode);
			}

			if (wire_errcode == WIRE_ERR_NONE) {
				/* change the filter */
#ifdef IPC_USING_SHMEM_SEM
				semwait(semaphore);
#endif
				strcpy ((pktd_client_table+idc)->filter, pktd_prot_filter);
				(pktd_client_table+idc)->snaplen = pktd_prot_snaplen;
				(pktd_client_table+idc)->state = filter;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;

				/* a filter change in an entry that dumps to disk implies 
				 * checkpointing
				 */
				if ((pktd_client_table+idc)->file_pattern[0] != '\0') {
					if (pktd_prot_cp_time > 0) {
						(void) gettimeofday(&((pktd_client_table+idc)->cp_time), NULL);
						(pktd_client_table+idc)->cp_time_max = pktd_prot_cp_time;
					}
					if (pktd_prot_cp_length > 0) {
						(pktd_client_table+idc)->cp_length_max = pktd_prot_cp_length;
					}
					if (pktd_prot_cp_files > 0) {
						(pktd_client_table+idc)->cp_files= 0;
						(pktd_client_table+idc)->cp_files_max = pktd_prot_cp_files;
					}

					/* checkpoint the file to disk */
					(pktd_client_table+idc)->state = checkpoint;
					pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
				}

#ifdef IPC_USING_SHMEM_SEM
				sempost(semaphore);
#endif

			} else {
				return -1;
			}

			table_refresh_needed = 1;
			break;


		case PROT_TYPE_WIRE_STATS:
		case PROT_TYPE_WIRE_DONE:
			wire_errcode = WIRE_ERR_NONE;

			/* check the client has already registered */
#ifdef IPC_USING_SHMEM_SEM
			semwait(semaphore);
#endif
			idc = pktd_cookie2index (pktd_prot_cookie);
#ifdef IPC_USING_SHMEM_SEM
			sempost(semaphore);
#endif

			if (idc <= 0) {
				wire_errcode = WIRE_ERR_PKTD_BAD_COOKIE;
				stat.ps_recv = 0;
				stat.ps_drop = 0;
				stat.ps_ifdrop = 0;

			} else {
				/* get statistics */
				pktd_get_stats ((pktd_client_table+idc)->device, &stat);
			}

			/* send the answer */
			if (wire_errcode == WIRE_ERR_NONE) {
				if (pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode, 
						stat.ps_recv, stat.ps_drop, stat.ps_ifdrop) < 0) {
					/* if we can't write to the control socket, close the entry anyway */
					wire_errcode = WIRE_ERR_PROT_SENDING_DATA;
				}
			} else {
				pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode);
			}

			if (command == PROT_TYPE_WIRE_DONE) {
				/* mark the entry as wire_done'd */
#ifdef IPC_USING_SHMEM_SEM
				semwait(semaphore);
#endif
				(pktd_client_table+idc)->state = closing;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
#ifdef IPC_USING_SHMEM_SEM
				sempost(semaphore);
#endif
				table_refresh_needed = 1;
			}
			break;


		case PROT_TYPE_WIRE_FLUSH:
			wire_errcode = WIRE_ERR_NONE;

			/* check the client has already registered */
#ifdef IPC_USING_SHMEM_SEM
			semwait(semaphore);
#endif
			idc = pktd_cookie2index (pktd_prot_cookie);
#ifdef IPC_USING_SHMEM_SEM
			sempost(semaphore);
#endif

			if (idc <= 0) {
				wire_errcode = WIRE_ERR_PKTD_BAD_COOKIE;

			} else {
				/* flush the client buffer */
				pktd_flush_client(idc);
			}


			/* send the answer */
			if (wire_errcode == WIRE_ERR_NONE) {
				if (pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode) < 0) {
					/* if we can't write to the control socket, close the entry anyway */
					wire_errcode = WIRE_ERR_PROT_SENDING_DATA;
				}
			} else {
				pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode);
			}

			break;


		case PROT_TYPE_WIRE_INJECT:
			wire_errcode = WIRE_ERR_NONE;

			/* check the client has already registered */
#ifdef IPC_USING_SHMEM_SEM
			semwait(semaphore);
#endif
			idc = pktd_cookie2index (pktd_prot_cookie);
#ifdef IPC_USING_SHMEM_SEM
			sempost(semaphore);
#endif

			if (idc <= 0) {
				wire_errcode = WIRE_ERR_PKTD_BAD_COOKIE;

			/* check packet injection is enabled */
			} else if (packet_injection_allowed == 0) {
				wire_errcode = WIRE_ERR_PKTD_WRITE_DISABLED;

#if (defined(LIBNET_BIG_ENDIAN) || defined(LIBNET_LIL_ENDIAN))
			/* check the client has permission to write the packet */

			} else if (pktd_write_permission (pktd_prot_ip, idc) < 0) {
				/* XXX: this should be protected by semaphores */
				wire_errcode = WIRE_ERR_PKTD_CLIENT_UNAUTHORIZED_WRITE;

				/* inject the packet */
			} else if (injection_write_ip (pktd_prot_ip) < 0) {
				wire_errcode = WIRE_ERR_PKTD_INJECTION_WRITE_IP;

			} else {
				debug2 ("injecting packet (IP length = %i)\n", 
						ntohs(*(u_int16_t*)(pktd_prot_ip+2)));
				debug3 ("\t");
				for (i = 0; i < ntohs(*(u_int16_t*)(pktd_prot_ip+2)); i++) {
					debug3 ("%02x", *(u_int8_t *)(pktd_prot_ip+i));
					if ((i % 4) == 3) {
						debug3 ("\n\t");
					} else {
						debug3 (".");
					}
				}
				debug3 ("\n");

#else
			} else {
				wire_errcode = WIRE_ERR_PKTD_WRITE_DISABLED;
#endif
			}

			/* send the answer */
			if (wire_errcode == WIRE_ERR_NONE) {
				if (pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode) < 0) {
					/* if we can't write to the control socket, just forget the request */
					return -1;
				}
			} else {
				pktd_send (fd, PROT_TYPE_ANSWER, command, wire_errcode);
			}

			table_refresh_needed = 0;
			break;


		default:
			/* bad message. Just forget it */
			verbose ("bad message\n");
			return -1;
	}

	if (table_refresh_needed) {
		/* report the fmgr about the new entry values so that it can change 
		 * the filter */
		pktd_refresh_client_table(idc);
	}

  return 0;
}



/*
 * pktd_get_filename
 *
 * Description:
 *	- Gets a filename for a packet dump
 *
 * Inputs:
 *	- pattern: a pattern to use as a basis of the file name
 *	- number: a number to substitute such pattern
 *
 * Output:
 *	- filename: the name of the file is written
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_get_filename (const char *pattern, int number, char *filename)
{
	struct stat sb;
	char *legal_pattern = "[a-zA-Z0-9._-]*%d[a-zA-Z0-9._-]*";
	regex_t reg;
	size_t nmatch = 1;
	regmatch_t pmatch;
	int status;

#ifndef REG_BASIC
#define REG_BASIC 0
#endif


	/* if the pattern is empty use the default base pattern */
	if (pattern[0] == '\0') {
		strcpy (filename, pktd_base_file_pattern);
	} else {
		strcpy (filename, pattern);
	}

	/* compile the legal-pattern regex filter */
	memset(&reg, 0, sizeof(regex_t));
	if (regcomp (&reg, legal_pattern, REG_BASIC) < 0) {
		wire_errcode = WIRE_ERR_PKTD_INTERNAL;
		return -1;
	}

	/* check that the requested pattern is legal */
	status = regexec (&reg, filename, nmatch, &pmatch, 0);
	regfree(&reg);
	if ((status != 0) ||
			!(pmatch.rm_so == 0) ||
			!(pmatch.rm_eo == strlen(filename))) {
		/* illegal pattern */
		wire_errcode = WIRE_ERR_PKTD_ILLEGAL_PATTERN;
		return -1;
	}

	/* generate the filename correctly */
	sprintf (filename, filename, number);
	{
		char tmp_filename[PROT_MAXFILENAME];
		sprintf (tmp_filename, "%s/%s", pktd_base_directory, filename);
		strcpy (filename, tmp_filename);
	}

	/* check that it can be open without problems */
	if (stat (filename, &sb) == 0) {
		/* try to delete it */
		if (unlink (filename) < 0) {
			wire_errcode = WIRE_ERR_PKTD_CANT_OPEN_FILE;
			return -1;
		}
	}

	return 0;
}




/*
 * pktd_get_device
 *
 * Description:
 *	- Gets a device for a given snaplen
 *
 * Inputs:
 *	- snaplen: the snaplen required by the client
 *
 * Output:
 *	- return: the device id
 *
 */
int pktd_get_device (u_int snaplen)
{
	int idd;
	int device = -1;
	u_int device_snaplen = 0;

	for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
		if (((pktd_device_table+idd)->datalink >= 0) &&
				(snaplen <= (pktd_device_table+idd)->snaplen) &&
				(((pktd_device_table+idd)->snaplen < device_snaplen) ||
				(device_snaplen == 0))) {
			device = idd;
			device_snaplen = (pktd_device_table+idd)->snaplen;
		}
	}

	debug1 ("using device %i (snaplen %d). Requested %d\n", 
			device, (pktd_device_table+device)->snaplen, snaplen);

	return device;
}




/*
 * pktd_free_entry
 *
 * Description:
 *	- Gets the id for a free position inside the connection table
 *
 * Output:
 *	- return: the position id if ok, <0 if there were problems
 *
 */
int pktd_free_entry()
{
	int idc;

	for (idc = 1; idc < DAEMON_MAX_CLIENTS; idc++) {
		if ((pktd_client_table+idc)->state == empty) {
			/* free entry */
			return idc;
		}
	}

	/* table full */
	return -1;
}


/*
 * pktd_cookie2index
 *
 * Description:
 *	- Gets the client table entry corresponding to the cookie
 *
 * Inputs:
 *	- cookie: the cookie whose table entry we want to know
 *
 * Output:
 *	- return: the position id if ok, <0 if there were problems
 *
 */
int pktd_cookie2index (u_int32_t cookie)
{
	int idc;

	for (idc = 1; idc < DAEMON_MAX_CLIENTS; idc++) {
		if ((pktd_client_table+idc)->cookie == cookie) {
			/* gotcha! */
			return idc;
		}
	}

	return -1;
}



/*
 * pktd_filter_permission
 *
 * Description:
 *	- Decides if it is right to accept a filter for a process. The process 
 *		is identified by a tuple (uid, gid, pid)
 *
 * Inputs: 
 *	- uid, gid, pid: the process that requested the filter
 *	- filter: the filter
 *	- idc: used to avoid generating the same cookie for two different requests
 *
 * Outputs: 
 *	- the cookie generated if ok, 0 if the request is illegal
 *
 */
u_int32_t pktd_filter_permission (u_int32_t uid, u_int32_t gid, u_int32_t pid, 
		char *filter, u_int snaplen, int idc)
{
	struct bpf_program program;
	int datalink;

	/* to check if a device can be compiled, any device will serve */
	datalink = (pktd_device_table+0)->datalink;

	/* check that the filter is valid */
	if (pktd_compile_filter (filter, snaplen, datalink, &program) < 0) {
		return (u_int32_t) 0;
	}

	/* free the memory used by the program (we're just checking if it's 
	 * a correct filter, not installing it)
	 */
	free (program.bf_insns);

	/* XXX: the cookie is really simple (the position in the table) */
	return (u_int32_t) idc;
}



/*
 * pktd_write_permission
 *
 * Description:
 *	- Decides if it is right to write a packet for a process. The process 
 *		is identified by a tuple (uid, gid, pid)
 *
 * Inputs: 
 *	- ip: the packet to be written
 *	- idc: the client identifier
 *
 * Outputs: 
 *	- return: 0 if ok to write, <0 otherwise
 *
 */
int pktd_write_permission (u_char *ip, int idc)
{
	/* XXX: we should add some security here */

	/* XXX: the mechanism to decide if a packet may be written is basic */
	return 0;
}



/*
 * pktd_detach
 *
 * Description:
 *	- Detaches a child to run a function. Returns the child's pid
 *
 * Inputs: 
 *	- funp: the function that the detached child will execute as its main
 *	- argv: arguments used by the function
 *
 * Outputs: 
 *	- the child pid for the parent, 0 for the child, <0 if there were problems
 *
 */
pid_t pktd_detach (void (*funp) (void *), void *argv)
{
	pid_t child_pid;

	/* detach a child to execute the function passed as argument */
	switch (child_pid = fork()) {
		case -1:
			perror("fork()");
			break;

		case 0:
			/* child process */
			(*funp) (argv);
			/* we shouldn't ever be here */
			perror ("daemon.c::pktd_detach: funp shouldn't ever return");
			exit (2);
			break;

		default:
			/* parent process */
			break;
	}

	return child_pid;
}




/*
 * pktd_smgr_main
 *
 * Description:
 *	- smgr process main. It listens to client requests and, if IPC 
 *		is carried out using sockets, to the fmgr process as well. 
 *
 * Inputs: 
 *	- argv: arguments used by the function
 *
 */
void pktd_smgr_main (void *argv)
{
	u_int port;
	socklen_t alen;
	struct sockaddr_in saddr;
#ifdef IPC_USING_SOCKETS
	int fd;
#endif


	debug1 ("pktd_smgr_main(%d): initializing smgr\n", (int)getpid());


#ifdef IPC_USING_SOCKETS
	/* accept the client socket */
	memset (&saddr, 0, sizeof(saddr));
	alen = sizeof(saddr);
	if ((fd = accept (ipc_socket, (struct sockaddr *)&saddr, &alen)) < 0) {
		error ("accept(): %s (%d)\n", sys_errlist[errno], errno);
		pktd_exit (1);
	}
	close (ipc_socket);
	ipc_socket = fd;
#endif


	/* create the external socket */
	port = PROT_SERVERPORT;
	if ((main_socket = pktd_server_socket (&port)) < 0) {
		error ("Cannot open main server socket (%s): %s (%d)\n",
				wire_err_msg(), sys_errlist[errno], errno);
		pktd_exit(1);
	}

	/* devote your life to serve requests */
	while (1) {
		int ctrlfd;

#ifdef IPC_USING_SOCKETS
		fd_set fds;
		int result;
		int nfds;

		FD_ZERO (&fds);
		FD_SET (main_socket, &fds);
		FD_SET (ipc_socket, &fds);
		nfds = getdtablesize();
		if ((result = select (nfds, &fds, NULL, NULL, NULL)) < 0) {
			error ("parent - error during select");
			exit (1);
		}

		/* if there's a message from the fmgr process, serve it */
		if (FD_ISSET (ipc_socket, &fds)) {
			/* message from the filter process */
			(void)pktd_serve_fmgr (ipc_socket);
			continue;
		}

		/* if this isn't a message from a client, go back to the select */
		if (!FD_ISSET (main_socket, &fds)) {
			continue;
		}
#endif

		/* a message from a client: serve it */
		memset (&saddr, 0, sizeof(saddr));
		alen = sizeof(saddr);
		if ((ctrlfd = accept (main_socket, (struct sockaddr *)&saddr, &alen)) < 0) {
			error ("accept(): %s (%d)\n", sys_errlist[errno], errno);
			pktd_exit(1);
		}
		(void)pktd_serve_client (ctrlfd);

		/* close the socket. As the traffic between clients and the daemon 
		 * is expected to be low, we have opted for opening a new socket 
		 * every time they have some information to exchange and closing 
		 * it afterwards, instead of keeping the socket open
		 */
		(void)close (ctrlfd);
	}

	/* close sockets used */
	close(main_socket);
#ifdef IPC_USING_SOCKETS
	close(ipc_socket);
#endif

	/* clean exit */
	pktd_exit(0);
	return;
}




/*
 * pktd_fmgr_main
 *
 * Description:
 *	- fmgr-process main. It installs the pcap filters and keeps 
 *		listening to the returned descriptors. When a packet is received,
 *		it forwards it to any client that has to receive it
 *
 * Inputs: 
 *	- argv: arguments used by the function
 *
 */
void pktd_fmgr_main (void *argv)
{
	int idd;
	fd_set fds;
	int result;
	int nfds;
	int npackets;

	debug1 ("pktd_fmgr_main(%d): initializing filters (%s)\n", (int)getpid(), 
			null_filter);

#ifdef IPC_USING_SOCKETS
	/* close the IPC socket as server and open it as client */
	close (ipc_socket);
	if ((ipc_socket = pktd_client_socket (ipc_port)) < 0) {
		error ("pktd_client_socket(): %s (%d)\n", wire_err_msg(), wire_errcode);
		pktd_exit(1);
	}
#endif


	/* initialize the pcap devices */
	/* we require the first device to be open */
	if (_wire_init (0, null_filter, pktd_interface, 65535, NULL) < 0) {
		/* die */
		error ("_wire_init(): cannot open %s network device: %s\n",
				pktd_interface, wire_err_msg());
		pktd_exit(1);
	}

	/* if the fast device cannot be open, we'll work without it */
	/* NOTE: this is the only part of the code where we assume 
	 * DAEMON_NUM_DEVICES == 2 */
	if (_wire_init (1, null_filter, pktd_interface, 
			(pktd_device_table+0)->hdr_size + DAEMON_SNAPLEN_FAST_DEVICE, 
			NULL) < 0) {
		/* log we couldn't open more pcap devices */
		log ("_wire_init(): %s\n", wire_err_msg());
	}

	while (1) {
		FD_ZERO (&fds);

		/* filter packets... */
		for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
			(void)_wire_set_fds(idd, &fds);
		}

#ifdef IPC_USING_SOCKETS
		/* ... while listening to the ipc socket */
		FD_SET (ipc_socket, &fds);
#endif

		/* get the maximum fds */
		nfds = -1;
		for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
			nfds = MAXIMUM(_wire_max_fd(idd), nfds);
		}
#ifdef IPC_USING_SOCKETS
		nfds = MAXIMUM(nfds, ipc_socket);
#endif
		nfds++;

		if ((result = select (nfds, &fds, NULL, NULL, NULL)) < 0) {
			if (errno == EINTR) {
				continue;
			}
			log ("select(): %s (%d)\n", sys_errlist[errno], errno);
		}

		/* if there's a packet from any pcap device, process it */
		for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
			if (FD_ISSET (_wire_get_fds(idd), &fds)) {
				npackets = pcap_dispatch((pktd_device_table+idd)->pd, -1, 
						pktd_callback, (void *)&idd);
			}
		}

#ifdef IPC_USING_SOCKETS
		/* if there's a message from the smgr process, read it */
		if (FD_ISSET (ipc_socket, &fds)) {
			(void)pktd_serve_smgr (ipc_socket);
		}
#endif

	}
	return;
}



/*
 * pktd_signal_handler
 *
 * Description:
 *	- Handles all signals in both processes (smgr and fmgr). The way 
 *		this works is that only the parent process can stop everything. 
 *		Therefore, if the child receives any terminating signal, it must 
 *		forward it to the parent
 *
 * Inputs: 
 *	- signum: the signal number
 *
 */
void pktd_signal_handler (int signum)
{
	/* trying to write to closed descriptors will raise SIGPIPE. Forget it */
	if (signum == SIGPIPE) {
		return;
	}

	debug1 ("%d: signal %d (kill_done = %d)\n", (int)getpid(), signum, 
			pktd_kill_done);

	if (getpid() == pktd_pid[SMGR_PID]) {
		/* this is the parent process */

		if (signum == SIGCHLD) {
			/* one of the children died: just wait for his status report
			 * wait4 waits for everybody. The following line only ends up when 
			 * the return code is < 0, which means that a signal was received 
			 * by the waiting process (0 means nothing happened and > 0 
			 * indicates the pid of the reporting child)
			 */
			return;
		}

		/* if the kill process is not prepared we cannot exit cleanly */
		if (!pktd_kill_done) {
			pktd_exit(1);
		}

	} else {
		/* this is the child process. Forward the signal to the parent */
		kill (pktd_pid[FMGR_PID], SIGTERM);
		pktd_exit(1);
	}

	exit (1);
}



/*
 * pktd_special_signal_handler
 *
 * Description:
 *	- Handles the special signal (SIGUSR1) that the parent and the child 
 *		use to signal events among themselves
 *
 * Inputs: 
 *	- signum: the signal number (it's required)
 *
 */
void pktd_special_signal_handler (int signum)
{
	if (getpid() == pktd_pid[SMGR_PID]) {
		/* this is the parent process */
		return;
	}

	/* in this case, the child process (the fmgr) has received the signal 
	 * from the parent (the smgr). This signal means that the smgr 
	 * requests attention for a change it made in the common table, 
	 * pktd_client_table
	 */

#ifdef IPC_USING_SHMEM_SEM
	/* lock the semaphore */
	semwait(semaphore);
#endif

	pktd_client_table_change ();

#ifdef IPC_USING_SHMEM_SEM
	/* unlock the semaphore */
	sempost(semaphore);
#endif

	return;
}



/*
 * pktd_client_table_change
 *
 * Description:
 *	- Restablishes coherence in pktd_client_table after a change has 
 *		been made. This means checking every entry and modifying its 
 *		state as required by its contents
 *
 */
void pktd_client_table_change ()
{
	int idc, idd;
	char *template = "(%s) or (%s)";
	char filename[PROT_MAXFILENAME];
	int fd;
	char new_filter[DAEMON_NUM_DEVICES][PROT_MAX_COMPOSED_FILTER];


	/* empty the new device filters */
	for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
		new_filter[idd][0] = '\0';
	}

	for (idc = 0; idc < DAEMON_MAX_CLIENTS; idc++) {

		/* this switch implements the FSM */
		switch ((pktd_client_table+idc)->state) {

			case empty:
				/* unused entry */
				break;


			case init:
				/* this entry has received wire_init */

				if ((pktd_client_table+idc)->file_pattern[0] == '\0') {
					/* the client requested receiving his packets through a socket */

					/* open the client data socket */
					fd = pktd_client_socket ((pktd_client_table+idc)->port);
					if (fd < 0) {
						/* problems opening datafp */
						(pktd_client_table+idc)->port = 0;
						(pktd_client_table+idc)->datafp = NULL;
						(pktd_client_table+idc)->state = closing;
						pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
						break;
					}
					(pktd_client_table+idc)->datafp = lfdopen (fd, 8192);

				} else {
					/* the client requested his packets being dumped to a file */

					/* get the file name */
					if (pktd_get_filename ((pktd_client_table+idc)->file_pattern, 
							(pktd_client_table+idc)->cp_files, filename) < 0) {
						/* problems getting a file name */
						(pktd_client_table+idc)->port = 0;
						(pktd_client_table+idc)->datafp = NULL;
						(pktd_client_table+idc)->state = closing;
						pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
						break;
					}

					/* open the file */
					if (((pktd_client_table+idc)->datafp = lfopen (filename, 8192)) 
							== NULL) {
						/* problems opening datafp */
						(pktd_client_table+idc)->port = 0;
						(pktd_client_table+idc)->datafp = NULL;
						(pktd_client_table+idc)->state = closing;
						pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
						break;
					}

					/* write the file header */
					idd = (pktd_client_table+idc)->device;
					if (pktd_lfwrite_ext_header (
							(pktd_client_table+idc)->datafp, 
							(pktd_client_table+idc)->snaplen, 
							(pktd_device_table+idd)->datalink, 
							&(pktd_client_table+idc)->co, 
							(pktd_client_table+idc)->filter) < 0) {
						/* problems writing on datafp */
						(pktd_client_table+idc)->port = 0;
						(void)lfclose ((pktd_client_table+idc)->datafp);
						(pktd_client_table+idc)->datafp = NULL;
						(pktd_client_table+idc)->state = closing;
						pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
						break;
					}
					lfflush ((pktd_client_table+idc)->datafp);
				}

				/* reset the entry filter */
				(pktd_client_table+idc)->fp.bf_len = 0;

				/* next step is compiling and adding the filter */
				(pktd_client_table+idc)->state = filter;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;

				/* ensure that this entry is considered again */
				idc--;
				break;


			case filter:
				/* compiling and adding the filter */

				/* free the program memory, if needed */
				if ((pktd_client_table+idc)->fp.bf_len != 0) {
					(pktd_client_table+idc)->fp.bf_len = 0;
					free ((pktd_client_table+idc)->fp.bf_insns);
				}

				/* compile the filter */
				idd = (pktd_client_table+idc)->device;
				if (pktd_compile_filter ((pktd_client_table+idc)->filter, 
						(pktd_client_table+idc)->snaplen, 
						(pktd_device_table+idd)->datalink, 
						&((pktd_client_table+idc)->fp)) < 0) {
					/* problems compiling the filter */
					(pktd_client_table+idc)->port = 0;
					(void)lfclose ((pktd_client_table+idc)->datafp);
					(pktd_client_table+idc)->datafp = NULL;
					(pktd_client_table+idc)->state = closing;
					pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
					break;
				}

				/* next state is working */
				(pktd_client_table+idc)->state = working;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;

				/* ensure that this entry is considered again */
				idc--;
				break;


			case working:
				/* this entry is currently in correct use */

				/* add this filter to the corresponding device filter */
				idd = (pktd_client_table+idc)->device;
				if (strlen(new_filter[idd]) == 0) {
					/* first filter */
					strcpy (new_filter[idd], (pktd_client_table+idc)->filter);
				} else {
					/* sprintf (new_filter[dev], template, new_filter[dev], cl_filter); */
					char temp[PROT_MAX_COMPOSED_FILTER];
					sprintf (temp, template, new_filter[idd], 
							(pktd_client_table+idc)->filter);
					strcpy (new_filter[idd], temp);
				}
				break;


			case checkpoint:
				/* this entry needs to carry out a checkpoint */

				/* do the checkpoint */
				if (pktd_do_checkpoint (idc) != 0) {
					/* problems doing the checkpoint */
					(pktd_client_table+idc)->state = closing;
					pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
					break;
				}

				/* now change the filter. This is not always needed. Some 
				 * checkpoints are triggered by a filter change, and some 
				 * don't. We do it this way to simplify the finite state 
				 * machine
				 */
				(pktd_client_table+idc)->state = filter;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;

				/* ensure that this entry is considered again */
				idc--;
				break;


			case closing:
				/* this entry has received wire_done or is flaking out */

				/* reset the entry */
				(pktd_client_table+idc)->port = 0;
				if ((pktd_client_table+idc)->datafp != NULL) {
					(void)lfclose ((pktd_client_table+idc)->datafp);
					(pktd_client_table+idc)->datafp = NULL;
				}

				/* free the memory used for the internal filter tree */
				if ((pktd_client_table+idc)->fp.bf_len != 0) {
					(pktd_client_table+idc)->fp.bf_len= 0;
					free ((pktd_client_table+idc)->fp.bf_insns);
				}

				(pktd_client_table+idc)->state = empty;
				pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
				pktd_empty_entry (idc);
				break;
		}
	}


	for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
		/* if no entries are being used, use the default filters */
		if (strlen(new_filter[idd]) == 0) {
			strcpy (new_filter[idd], null_filter);
		}


		/* set the kernel filters that have changed */
		if (((pktd_device_table+idd)->pd != NULL) &&
				(strcmp (new_filter[idd], (pktd_device_table+idd)->filter) != 0)) {
			debug1 ("daemon.c::pktd_client_table_change: changing filter %i (%s)\n", 
					idd, new_filter[idd]);

			if (set_pcap_filter (idd, new_filter[idd]) < 0) {
				/* this shouldn't happen!! */
				error ("Cannot set device filter %s: %s (%d)\n", 
						(pktd_device_table+idd)->filter, sys_errlist[errno], errno);
				pktd_exit(1);
			}
		}
	}

	return;
}




/*
 * pktd_compile_filter
 *
 * Description:
 *	- Compiles a filter into a program
 *
 * Inputs:
 *	- filter: a string describing the filter
 *	- snaplen: the snaplen of the filter
 *	- datalink: the filter link type
 *
 * Output:
 *	- fp is filled with the new program result of the compilation
 *	- return: 0 if ok, <0 if there were problems
 *
 */
int pktd_compile_filter (char *filter, u_int snaplen, int datalink, 
		struct bpf_program *fp)
{
	int i;

	i = pcap_compile_nopcap (snaplen, datalink, fp, filter, 1, 0L);
	return i;
}



/*
 * pktd_exit
 *
 * Description:
 *	- A clean exit, ensuring the main socket is closed and the semaphore
 *		is destroyed
 *
 * Inputs:
 *	- code: the exit code
 *
 */
void pktd_exit (int code)
{
	int idc, idd;
	struct pcap_stat stat;

#ifdef IPC_USING_SHMEM_SEM
	/* clean up the semaphore or else we'll leak */
	(void)semdestroy (semaphore);
#if (defined(__linux__) || defined(__sun__))
	if (shmem_client_fd >= 0) {
		(void)close (shmem_client_fd);
		shmem_client_fd = -1;
	}
	if (shmem_device_fd >= 0) {
		(void)close (shmem_device_fd);
		shmem_device_fd = -1;
	}
#endif
#endif

#ifdef IPC_USING_SOCKETS
	/* close the IPC socket */
	(void)close (ipc_socket);
#endif

	/* close the main socket */
	if (getpid() == pktd_pid[SMGR_PID]) {
		/* this is the parent process */
		(void)close (main_socket);
	}


	/* fmgr termination */
	if (getpid() != pktd_pid[SMGR_PID]) {
/*
		netlogger_close(); // YYY
*/
		/* close all the file descriptors, buffered and unbuffered */
		for (idc = 0; idc < DAEMON_MAX_CLIENTS; idc++) {
			if ((pktd_client_table+idc)->datafp != NULL) {
				(void)lfclose ((pktd_client_table+idc)->datafp);
			}
		}
		/* close the pcap devices */
		for (idd = 0; idd < DAEMON_NUM_DEVICES; idd++) {
			pktd_get_stats (idd, &stat);
			debug1 ("pktd_exit: device %i statistics -> (%i, %i, %i)\n", 
					idd, stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);
			pcap_close((pktd_device_table+idd)->pd);
		}
	}


	/* kill all the children */
	if (getpid() == pktd_pid[SMGR_PID]) {
		/* this is the parent process */
		pktd_kill_done = 1;
		kill (0, SIGTERM);
	}

	exit (code);
	return;
}



/*
 * pktd_callback
 *
 * Description:
 *	- Callback function. It is called whenever a packet is received
 *
 * Inputs:
 *	- pkt: a pointer to the packet
 *	- ts: the time when the packet was received
 *	- len: the original packet length
 *	- caplen: the captured packet length. This is pkt length
 *	- user_data: user data containing a pointer to the device id
 *
 * NOTE:
 *	- There are two modes to send traffic to clients: 
 *		1) uncompressed mode: in this case, we send clients the full 
 *		packet captured by the daemon, including the datalink layer 
 *		header (typically Ethernet). This implies 70+ bytes per packet: 
 *		16 bytes for the pcap header (8-byte timestamp, 4-byte caplen, 
 *		4-byte length), 14 bytes for the Ethernet header, 20 bytes for 
 *		the IP header, 20+options bytes for the TCP header. 
 *		2) compressed mode: in this case, we send clients a compressed 
 *		version of the packets. Currently we compress the pcap header, 
 *		throw away the datalink header (it's useless for clients), and 
 *		compress the IP, UDP, and TCP headers. There's a document that
 *		explains the compression, but to give some numbers, FTP (TCP) 
 *		traffic gets reduced to 17 bytes/packet total, and UDP (synthetic) 
 *		traffic gets reduced to 6 bytes/packet total. 
 */
static void pktd_callback (u_char *user, const struct pcap_pkthdr *hdr,
		const u_char *pkt)
{
	int idc, idd;
	char packet_header[TCPDUMP_PACKET_HEADER_LENGTH];
	u_int caplen;
	int any_checkpoint = 0;
	int i = 0;
	u_char *comp_pkt;
	int comp_len;

	/* the device id */
	idd = *(int *)user;

	if (log_level >= SYSLOG_LEVEL_DEBUG3) {
		i += (pktd_device_table+idd)->hdr_size;
		debug3 ("%li.%06li %i.%i.%i.%i:%i > %i.%i.%i.%i:%i  (%i/%i)\n", 
				hdr->ts.tv_sec, hdr->ts.tv_usec, 
				(int)*(pkt+i+12), (int)*(pkt+i+13), (int)*(pkt+i+14), (int)*(pkt+i+15),
				(int)ntohs(*(u_short *)(pkt+i+ 4 * (int)((*(pkt+i+0))&0xf) )),
				(int)*(pkt+i+16), (int)*(pkt+i+17), (int)*(pkt+i+18), (int)*(pkt+i+19),
				(int)ntohs( *(u_short *)( pkt+i+2+4*(int)((*(pkt+i+0))&0xf) ) ),
				hdr->caplen, hdr->len);
		debug3 ("\tIP -> protocol: %i, length: %i\n", (int)*(pkt+i+9), (int)ntohs(*(u_int16_t *)(pkt+i+2)));
	}


	/* prepare the packet header */

	/* NOTE: we use network order, while tcpdump uses host order. Is this 
	 * a problem? Well, not really because we will write files in network 
	 * order, which is a type of host order like any other. 
	 */
	*(long *)(packet_header+0) = htonl((long)hdr->ts.tv_sec);
	*(long *)(packet_header+4) = htonl((long)hdr->ts.tv_usec);
	*(u_int32_t *)(packet_header+8) = htonl((u_int32_t)hdr->caplen);
	*(u_int32_t *)(packet_header+12) = htonl((u_int32_t)hdr->len);

#ifdef IPC_USING_SHMEM_SEM
	/* lock the semaphore */
	semwait(semaphore);
#endif

	for (idc = 0; idc < DAEMON_MAX_CLIENTS; idc++) {

		/* check the client entry is currently in use */
		/* NOTE: I wonder if we should check here if the entry state is 
		 * just working, as it is now, or something different than empty. 
		 * Anyway, should any change be made, be careful to only deliver 
		 * packets to entries whose state is "working"
		 */
		if (pktd_client_table_state[idc] != working) {
			continue;
		}


		/* check if this client is mapped to the calling device */
		if (idd != (pktd_client_table+idc)->device) {
			continue;
		}

		/* mark up any needed checkpoint. 
		 * NOTE: It's questionable whether this checkpoint need be done for every 
		 * working-state entry or just for the ones that match the filter. 
		 */
		any_checkpoint = pktd_mark_checkpoint (idc);

		/* check if the packet matches this entry's filter */
		if (pktd_match ((pktd_client_table+idc)->fp, pkt, hdr->len, 
				hdr->caplen)) {
			/* this connection is active and packet matches it -> send packet */

			/* do not send more bytes than the client's snaplen */
			caplen = hdr->caplen;
			if (caplen > (pktd_client_table+idc)->snaplen) {
				caplen = (pktd_client_table+idc)->snaplen;
				*(u_int32_t *)(packet_header+8) = htonl((u_int32_t)caplen);
			}

			if ((pktd_client_table+idc)->compression == 0) {
				if ((lfwrite ((pktd_client_table+idc)->datafp, packet_header, 
						TCPDUMP_PACKET_HEADER_LENGTH) < TCPDUMP_PACKET_HEADER_LENGTH) ||
						(lfwrite ((pktd_client_table+idc)->datafp, (void*)pkt, caplen) 
								< caplen)) {
					/* connection flaking out -> kill the entry */
					(pktd_client_table+idc)->state = closing;
					pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
					pktd_client_table_change ();
					continue;
				}
				(pktd_client_table+idc)->bytes_written += TCPDUMP_PACKET_HEADER_LENGTH;
				(pktd_client_table+idc)->bytes_written += caplen;

			} else {
				/* encode the packet */
				int paddings;
				encode_trace ((pktd_client_table+idc)->codec, 
						&(pktd_client_table+idc)->co, hdr, pkt, caplen, 
						(pktd_device_table+idd)->hdr_size, &comp_pkt, &comp_len);

				/* introduce restart markers if needed */
				if ((pktd_client_table+idc)->co.rm_offset != 0) {
					paddings = need_restart_markers (&(pktd_client_table+idc)->co, 
							(pktd_client_table+idc)->datafp, 
							comp_len, (pktd_client_table+idc)->bytes_written, 
							(pktd_client_table+idc)->codec);
					if (paddings < 0) {
						/* connection flaking out -> kill the entry */
						(pktd_client_table+idc)->state = closing;
						pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
						pktd_client_table_change ();
						continue;
					} else if (paddings > 0) {
						(pktd_client_table+idc)->bytes_written += paddings;
						/* there was a codec initialization => must reencode packet */
						encode_trace ((pktd_client_table+idc)->codec, 
								&(pktd_client_table+idc)->co, hdr, pkt, caplen, 
								(pktd_device_table+idd)->hdr_size, &comp_pkt, &comp_len);
					}
				}

				/* write the compressed packet */
				if (lfwrite ((pktd_client_table+idc)->datafp, comp_pkt, 
						comp_len) < comp_len) {
					/* connection flaking out -> kill the entry */
					(pktd_client_table+idc)->state = closing;
					pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
					pktd_client_table_change ();
					continue;
				}
				(pktd_client_table+idc)->bytes_written += comp_len;
			}

			if ((pktd_client_table+idc)->immediate_delivery == 1) {
				/* client requested immediate delivery of packets -> no buffering */
				lfflush ((pktd_client_table+idc)->datafp);
			}
		}
	}

	/* check if any of the entries was prepared to checkpoint */
	if (any_checkpoint) {
		pktd_client_table_change ();
	}

#ifdef IPC_USING_SHMEM_SEM
	/* unlock the semaphore */
	sempost(semaphore);
#endif

	return;
}




/*
 * pktd_match
 *
 * Description:
 *	- Checks if a packet matches a filter. It just wraps up a call to 
 *		bpf_filter.c::bpf_filter slightly modified so it doesn't require 
 *		a kernel running it
 *
 * Inputs:
 *	- fp: a BPF-compiled filter
 *	- pkt: a pointer to the packet
 *	- len: the original packet length
 *	- caplen: the captured packet length. This is pkt length
 *
 * Output:
 *	- return: 1 if the packet matches the filter, 0 otherwise
 *
 */
#include "bpf_filter.c"

int pktd_match (struct bpf_program fp, const u_char *pkt, u_int len, 
		u_int caplen)
{
	int i;

	/* NOTE: I don't like too much un-const'ing the pkt variable */
	i = bpf_filter (fp.bf_insns, (u_char *)pkt, len, caplen);
	return i;
}




/*
 * pktd_do_checkpoint
 *
 * Description:
 *	- Carries out checkpointing
 *
 * Inputs:
 *	- idc: the identifier of the pktd_client_table entry
 *
 * Output:
 *	- return: 0 if after the checkpoint the entry keeps being in-use, 
 *	1 if it the maximum number of files were reached and therefore the 
 *	entry has to be closed, <0 if there were problems
 *
 */
int pktd_do_checkpoint (int idc)
{
	char filename[PROT_MAXFILENAME];

	/* close the old file */
	if ((pktd_client_table+idc)->datafp != NULL) {
		(void)lfclose ((pktd_client_table+idc)->datafp);
		(pktd_client_table+idc)->datafp = NULL;
	}

	/* bump up the file number */
	(pktd_client_table+idc)->cp_files++;

	/* check if this was the last file requested */

	/* XXX: What happens when the user selects the maximum number of 
	 * XXX	files to be 0? Now it creates infinite files, which may be 
	 * XXX	not a good idea
	 */
	if (((pktd_client_table+idc)->cp_files_max != 0) &&
			((pktd_client_table+idc)->cp_files >= (pktd_client_table+idc)->cp_files_max)) {
		/* this is the last one */
		return 1;
	}

	/* get the new time */
	(void) gettimeofday (&((pktd_client_table+idc)->cp_time), NULL);

	/* get the new file name */
	if (pktd_get_filename ((pktd_client_table+idc)->file_pattern, 
			(pktd_client_table+idc)->cp_files, filename) < 0) {
		/* problems getting a file name */
		return -1;
	}

	/* open the new file */
	if (((pktd_client_table+idc)->datafp = lfopen (filename, 8192)) == NULL) {
		/* problems opening datafp */
		return -1;
	}

	/* write the header */
	if (pktd_write_header (lfileno((pktd_client_table+idc)->datafp), 
			(pktd_client_table+idc)->snaplen, 
			(pktd_device_table+(pktd_client_table+idc)->device)->datalink) < 0) {
		/* problems writing on datafp */
		return -1;
	}

	debug1 ("pktd_do_checkpoint: Checkpointing entry %i to %s\n", idc, filename);
	return 0;
}




/*
 * pktd_mark_checkpoint
 *
 * Description:
 *	- Checks if an entry has to be checkpointed
 *
 * Inputs:
 *	- idc: the pktd_client_table entry it has to check
 *
 * Output:
 *	- return: 1 if it marked the entry as cp, 0 if not, <0 if problems
 *
 */
int pktd_mark_checkpoint (int idc)
{
	struct timeval current_time;
	struct stat sb;

	/* check that the entry is in working use and dumps its packet to a file */
	if (((pktd_client_table+idc)->state != working) || 
			((pktd_client_table+idc)->file_pattern[0] == '\0')) {
		return 0;
	}

	/* check if a checkpoint is needed because of the time */
	if ((pktd_client_table+idc)->cp_time_max != 0) {
		(void)gettimeofday (&current_time, NULL);
		if ((current_time.tv_sec - (pktd_client_table+idc)->cp_time.tv_sec) > 
				(pktd_client_table+idc)->cp_time_max) {
			(pktd_client_table+idc)->state = checkpoint;
			pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
			return 1;
		}
	}

	/* check if a checkpoint is needed because of the file length */
	if ((pktd_client_table+idc)->cp_length_max != 0) {
		if (fstat (lfileno((pktd_client_table+idc)->datafp), &sb) < 0) {
			/* error getting the file data */
			return -1;
		}
		if (sb.st_size > (pktd_client_table+idc)->cp_length_max * 1000) {
			(pktd_client_table+idc)->state = checkpoint;
			pktd_client_table_state[idc] = (pktd_client_table+idc)->state;
			return 1;
		}
	}

	return 0;
}



/*
 * pktd_install_signal_handlers
 *
 * Description:
 *	- Installs handlers for all the signals
 *
 */
void pktd_install_signal_handlers ()
{
	struct sigaction action, old_action;
	int num;

	/* fill the sigaction structure */
	sigfillset(&action.sa_mask);
	action.sa_flags = 0;

#if (defined(__FreeBSD__) && (__FreeBSD__ >= 4))
	for (num = 1; num < _SIG_MAXSIG; num++) {
#else
	for (num = 1; num < NSIG; num++) {
#endif
		switch (num) {
			case SIGKILL:
			case SIGSTOP:
				/* non-catchable signals */
				break;

			case SIGUSR1:
				/* special signal */
				action.sa_handler = pktd_special_signal_handler;
				action.sa_flags = 0;
				if (sigaction (num, &action, &old_action) == -1) {
					log ("sigaction(): %s (%d)\n", sys_errlist[errno], errno);
				}
				break;

			default:
				/* all the remain signals */
				action.sa_handler = pktd_signal_handler;
				action.sa_flags = 0;
				if (sigaction (num, &action, &old_action) == -1) {
					log ("sigaction(): %s (%d)\n", sys_errlist[errno], errno);
				}
				break;
		}
	}

	return;
}




/*
 * _wire_init
 *
 * Description:
 *	- Installs a packet filter using the pcap library
 *
 * Inputs:
 *	- idd: index to the device table
 *	- filter: a string describing the filter to be installed
 *	- interface: network interface to be read
 *	- snaplen: the packet capture snaplen
 *	- read_file: file to be read
 *
 * Output:
 *	- return: 0 if correct, <0 if there were problems
 *
 */
int _wire_init (int idd, const char *filter, const char *interface,
		u_int snaplen, const char *read_file)
{
	wire_errcode = WIRE_ERR_NONE;

	/* open the pcap device */
	if (read_file) {
		/* get the packets from a tcpdump file */
		reading_offline = 1;
		(pktd_device_table+idd)->pd = open_pcap_file (idd, read_file);
		if ((pktd_device_table+idd)->pd == NULL) {
			wire_errcode = WIRE_ERR_PKTD_CANT_OPEN_FILE;
			return -1;
		}


	} else {
		/* get the packets from a live device */
		(pktd_device_table+idd)->snaplen = snaplen;
		(pktd_device_table+idd)->pd = open_pcap_interface (idd, interface);
		if ((pktd_device_table+idd)->pd == NULL) {
			if (wire_errcode == WIRE_ERR_NONE) {
				wire_errcode = WIRE_ERR_PKTD_CANT_OPEN_FILTER;
			}
			return -1;
		}

	}


	/* set the filter */
	if (set_pcap_filter (idd, filter) != 0) {
		return -1; 
	}


	/* get the link layer type (e.g., DLT_EN10MB) */
	(pktd_device_table+idd)->datalink = 
			pcap_datalink((pktd_device_table+idd)->pd);

	/* get the datalink header size */
	if (((pktd_device_table+idd)->hdr_size = pktd_get_hdr_size 
			((pktd_device_table+idd)->datalink)) < 0) {
		wire_errcode = WIRE_ERR_PKTD_UNKNOWN_LINK_TYPE;
		return -1;
	}

#ifdef IPC_USING_SOCKETS
	pktd_report_device_info (idd);
#endif

	return 0;
}




/*
 * _wire_max_fd
 */
int _wire_max_fd (int idd)
{
	return ((pktd_device_table+idd)->pd != NULL) ? 
			pcap_fileno((pktd_device_table+idd)->pd) : -1;
}



/*
 * _wire_set_fds
 */
int _wire_set_fds (int idd, fd_set *fds)
{
	if ((pktd_device_table+idd)->pd == NULL) {
		return -1;
	}

	FD_SET(pcap_fileno((pktd_device_table+idd)->pd), fds);
	return 0;
}



/*
 * _wire_get_fds
 */
int _wire_get_fds (int idd)
{
	if ((pktd_device_table+idd)->pd == NULL) {
		return 0;
	}

	return pcap_fileno((pktd_device_table+idd)->pd);
}




/*
 * Some useful lower-level code
 */

/*
 * set_pcap_filter
 *
 * Description:
 *	- Compiles and installs a filter in the daemon handler
 *
 * Inputs:
 *	- idd: index to the device table
 *	- filter: a string describing the filter to be installed
 *
 * Output:
 *	- return: 0 if correct, <0 if there were problems
 *
 */
static int set_pcap_filter (int idd, const char *filter)
{
	int optimize = 1;
	static struct bpf_insn null_insn = PKTD_BPF_NULL_FILTER;

	/* compile the filter */
	if (strcmp (filter, null_filter) != 0) {
		if (pcap_compile((pktd_device_table+idd)->pd, 
				&(pktd_device_table+idd)->fcode, (char *) filter, optimize, 
				(pktd_device_table+idd)->netmask) < 0) {
			debug1 ("set_pcap_filter: Error compiling filter: %s\n", 
					pcap_geterr((pktd_device_table+idd)->pd));
			wire_errcode = WIRE_ERR_PKTD_FILTER;
			return -1;
		}
	} else {
		(pktd_device_table+idd)->fcode.bf_len = PKTD_BPF_NULL_FILTER_LEN;
		(pktd_device_table+idd)->fcode.bf_insns = &null_insn;
	}


	/* account for packet statistics before setting new filter */
	if (strcmp ((pktd_device_table+idd)->filter, null_filter) != 0) {
		struct pcap_stat stat;
		if (pcap_stats((pktd_device_table+idd)->pd, &stat) < 0) {
			stat.ps_recv = 0;
			stat.ps_drop = 0;
			stat.ps_ifdrop = 0;
		}
		/* add stats to total_stat */
		(pktd_device_table+idd)->total_stat.ps_recv += stat.ps_recv;
		(pktd_device_table+idd)->total_stat.ps_drop += stat.ps_drop;
		(pktd_device_table+idd)->total_stat.ps_ifdrop += stat.ps_ifdrop;
	}


	/* install the filter */
	if (pcap_setfilter((pktd_device_table+idd)->pd, 
			&(pktd_device_table+idd)->fcode) < 0) {
		debug1 ("set_pcap_filter: Error setting filter: %s\n", 
				pcap_geterr((pktd_device_table+idd)->pd));
		wire_errcode = WIRE_ERR_PKTD_FILTER;
		return -1;
	}


	/* account for packet statistics after setting new filter */
	if (strcmp (filter, null_filter) != 0) {
		struct pcap_stat stat;
		if (pcap_stats((pktd_device_table+idd)->pd, &stat) < 0) {
			stat.ps_recv = 0;
			stat.ps_drop = 0;
			stat.ps_ifdrop = 0;
		}
		/* write up last_stat */
		(pktd_device_table+idd)->last_stat.ps_recv = stat.ps_recv;
		(pktd_device_table+idd)->last_stat.ps_drop = stat.ps_drop;
		(pktd_device_table+idd)->last_stat.ps_ifdrop = stat.ps_ifdrop;
	}


	/* copy the filter into the packet capture descriptor fcode (this is NOT 
	 * done by pcap_setfilter)
	 */
	(pktd_device_table+idd)->pd->fcode = (pktd_device_table+idd)->fcode;

	/* copy the filter string to the device descriptor */
	strcpy ((pktd_device_table+idd)->filter, filter);

	return 0;
}



/*
 * open_pcap_file
 *
 * Description:
 *	- Associates a packet capture descriptor to a file
 *
 * Inputs:
 *	- idd: device table entry to refresh
 *	- read_file: a string describing the file which is to be read
 *
 * Output:
 *	- return: the packet capture descriptor if correct, NULL if problems
 *
 */
static pcap_t *open_pcap_file (int idd, const char *read_file)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;

	/* open the file */
	if ( ! (pd = pcap_open_offline((char*) read_file, errbuf)) ) {
		wire_errcode = WIRE_ERR_PKTD_NO_SUCH_FILE;
		return NULL;
	}

	/* set the network mask */
	(pktd_device_table+idd)->netmask = 0L;

	return pd;
}



/*
 * open_pcap_interface
 *
 * Description:
 *	- Associates a packet capture descriptor to a network interface
 *
 * Inputs:
 *	- idd: device table entry to refresh
 *	- interface: a string describing the network interface to be read
 *
 * Output:
 *	- return: the packet capture descriptor if correct, NULL if there were 
 *	problems
 *
 */
static pcap_t *open_pcap_interface (int idd, const char *interface)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net;
	int timeout;
	pcap_t *pd;
#if defined(__FreeBSD__)

	int set_immediate = 1;

#endif

	/* determine interface if not specified */
	if (!interface && !(interface = pcap_lookupdev(errbuf))) {
		wire_errcode = WIRE_ERR_PKTD_PCAP;
		return NULL;
	}

	/* determine network and netmask */
	if (pcap_lookupnet((char *) interface, &net, 
			&(pktd_device_table+idd)->netmask, errbuf) < 0) {
		/*
			From http://ethereal.ntop.org/lists/ethereal-users/200009/msg00108.html
		
			"What tcpdump (the LBL 3.4 version, at least) does in this situation is
			to print the message in question ("dc0: no IPv4 address assigned", or
			whatever) as a warning, and then set the IP address and netmask to 0. 
			This means that filtering that cares about the netmask (checks for
			IP broadcast addresses - as they check not only for 255.255.255.255 but
			also for the broadcast address for the network) won't necessarily work,
			and the tests done by tcpdump's "-f" flag won't work, but everything
			else should, from a quick look at the code, work."

			Why shouldn't it work for us? ;)
		*/


		net = 0;
		(pktd_device_table+idd)->netmask = 0;
		verbose ("Couldn't find net/netmask (%s)", errbuf);
	}

	/* convert the net to network order. We don't convert netmask because 
	 * we don't know if pcap_compile wants the netmask in host or network 
	 * order. As it is currently (network order) works, so we won't touch 
	 * it
	 */
	net = ntohl(net);
	debug1 ("Opening device %s on network %d.%d.%d.%d (mask %d.%d.%d.%d, snaplen = %d)\n", 
			interface,
			((u_int32_t)net)>>24 & 0x00ff, ((u_int32_t)net)>>16  & 0x00ff,
			((u_int32_t)net)>>8  & 0x00ff, ((u_int32_t)net)>>0 & 0x00ff,
			((u_int32_t)ntohl((pktd_device_table+idd)->netmask))>>24 & 0x00ff,
			((u_int32_t)ntohl((pktd_device_table+idd)->netmask))>>16 & 0x00ff, 
			((u_int32_t)ntohl((pktd_device_table+idd)->netmask))>>8  & 0x00ff,
			((u_int32_t)ntohl((pktd_device_table+idd)->netmask))>>0  & 0x00ff,
			(pktd_device_table+idd)->snaplen);

	/* open the network interface */

	/* NOTE: In Linux, the way to open the network interface in promiscuous 
	 * mode is by opening a socket in the domain PF_PACKET, with the type 
	 * SOCK_RAW, and selecting the protocol to be ETH_P_ALL in network order 
	 * (i.e., htons(ETH_P_ALL) ). The problem is that "only processes with 
	 * effective uid 0 or the CAP_NET_RAW capability may open packet 
	 * sockets" [tcpdump manual page]. This means that trying to run 
	 * the pktd daemon from a user other than the root will fail
	 */
	timeout = 1000;
	pd = pcap_open_live ((char *) interface, (pktd_device_table+idd)->snaplen, 
			1, timeout, errbuf);
	if (pd == NULL) {
		/* report this problem to the user */
		error ("\nCouldn't open %s interface (%s). ", interface, errbuf);
		error ("Do you have permission to open it?\n");
		wire_errcode = WIRE_ERR_PKTD_PCAP;
		return NULL;
	}


#if defined(__FreeBSD__)
	/* we assume that the packet capture type is BPF iff this is FreeBSD. In 
	 * this case, we set the packet capture device to immediate mode
	 * From the libpcap 0.6.2 README, "BPF is standard in 4.4BSD, BSD/OS, 
	 * NetBSD, FreeBSD, and OpenBSD. DEC OSF/1 uses the packetfilter 
	 * interface but has been extended to accept BPF filters (which 
	 * libpcap utilizes)." This suggests we should ioctl with BIOCIMMEDIATE 
	 * for all these OSs, but we won't do it until we can try ourselves.
	 */

	if (ioctl(pcap_fileno(pd), BIOCIMMEDIATE, &set_immediate) < 0) {
		wire_errcode = WIRE_ERR_PKTD_IMMEDIATE_MODE;
		return NULL;
	}

#endif

	return pd;
}




/*
 * The semaphore code
 */

#ifdef IPC_USING_SHMEM_SEM

/* some semaphore definitions */
#define SEM_NAME "/tmp/pktd_sem%i"
#if defined(__sun__)
/* for any unknown reason this isn't defined on Solaris */
union semun {
	long val;
	struct semid_ds *buf;
	ushort *array;
};
#endif
#if (defined(_SEM_SEMUN_UNDEFINED) || defined(__linux__))
/* Linux wants you to define semun (check /usr/include/bits/sem.h ) */
union semun {
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};
#endif

/* I got these functions from Apache src/http_main.c */
static struct sembuf op_wait = {0, -1, SEM_UNDO};
#ifdef NODEF
static struct sembuf op_trywait = {0, -1, SEM_UNDO|IPC_NOWAIT};
#endif
static struct sembuf op_post = {0, 1, SEM_UNDO};


/*
 * seminit
 *
 * Description:
 *	- Initializes a semaphore
 *
 * Output:
 *	- return: the semaphore id, <0 if there were problems
 *
 */
static int seminit ()
{
	union semun ick;
	int sem_id;

	/* create the semaphore */
	if ((sem_id = semget (IPC_PRIVATE, 1, IPC_CREAT | 0600)) == -1) {
		if (errno == EINVAL) {
			error ("EINVAL\n");
		}
		if (errno == ENOSPC) {
			error ("ENOSPC\n");
			error ("Try ipcrm'ing all the semaphores (check them using ipcs)\n");
		}
		error ("semget(): %s (%d)\n", sys_errlist[errno], errno);
		return -1;
	}

	/* initialize the semaphore value */
	ick.val = 1;
	if (semctl(sem_id, 0, SETVAL, ick) < 0) {
		error ("semctl(): %s (%d)\n", sys_errlist[errno], errno);
		semdestroy (sem_id);
		return -1;
	}

	return sem_id;
}


/*
 * semwait
 *
 * Description:
 *	- Waits on a semaphore
 *
 * Inputs:
 *	- sem_id: the semaphore
 *
 */
static void semwait (int sem_id)
{
	while (semop(sem_id, &op_wait, 1) < 0) {
		if (errno != EINTR) {
			error ("semop(): %s (%d)\n", sys_errlist[errno], errno);
			pktd_exit(1);
		}
	}
}


#ifdef NODEF
/*
 * semtrywait
 *
 * Description:
 *	- Does trywait in a semaphore
 *
 * Inputs:
 *	- sem_id: the semaphore
 *
 * Output:
 *	- return: 0 if the semaphore was free, -1 if it was unlocked
 *
 */
static int semtrywait (int sem_id)
{
	while (semop(sem_id, &op_trywait, 1) < 0) {
		if (errno == EAGAIN) {
			/* the semaphore was locked */
			return -1;
		} else if (errno != EINTR) {
			error ("semop(): %s (%d)\n", sys_errlist[errno], errno);
			pktd_exit(1);
		}
	}
	return 0;
}
#endif


/*
 * sempost
 *
 * Description:
 *	- Posts on a semaphore
 *
 * Inputs:
 *	- sem_id: the semaphore
 *
 */
static void sempost (int sem_id)
{
	while (semop(sem_id, &op_post, 1) < 0) {
		if (errno != EINTR) {
			error ("semop(): %s (%d)\n", sys_errlist[errno], errno);
			pktd_exit(1);
		}
	}
}


/*
 * semdestroy
 *
 * Description:
 *	- Destroys a semaphore
 *
 * Inputs:
 *	- sem_id: the semaphore
 *
 * Output:
 *	- return: 0 if the semaphore was a valid one, -1 otherwise
 *
 */
static int semdestroy (int sem_id)
{
	if (sem_id >= 0) {
		union semun ick;
		ick.val = 0;
		return semctl(sem_id, 0, IPC_RMID, ick);
	}
	return -1;
}

#endif


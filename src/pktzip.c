/*
 * pktzip.c --
 *
 *  Tcpdump Trace Compressor/Uncompressor
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
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>


#include "lstdio.h"
#include "trace-codec.h"
#include "version.h"


char finname[PROT_MAXFILENAME];
char foutname[PROT_MAXFILENAME];

int uncompress_file (FILE *fin, lFILE *lfout, co_t *co);
int compress_file (FILE *fin, lFILE *lfout, struct pcap_file_header *filehdr, 
		int swapped);
void usage (char **argv);
void parse_args (int argc, char **argv);



/*
 * main
 *
 *	Main procedure. Sets default values, parses arguments from command line, 
 *	and calls uncompress or compress depending on the file linktype
 *
 */
int main (int argc, char **argv)
{
	FILE *fin;
	lFILE *lfout;
	struct pcap_file_header filehdr;
	int swapped;
	co_t co;
	char filter[PROT_MAX_INDIVIDUAL_FILTER];

	/* get the file names */
	finname[0] = '\0';
	foutname[0] = '\0';
	parse_args (argc, argv);


	/* open input file */
	if ((finname[0] == '-' && finname[1] == '\0') || (finname[0] == '\0')) {
		fin = stdin;
	} else {
		fin = fopen (finname, "r");
		if (fin == NULL) {
			fprintf (stderr, "Error: cannot open file %s\n", finname);
			exit (1);
		}
	}

	/* read the input header to know whether it's compressed or not */
	if (pktd_fread_header (fin, &filehdr, &swapped, &co, filter) < 0) {
		fprintf (stderr, "Error: file %s has wrong format\n", finname);
		exit (1);
	}


	if (filehdr.version_minor == 5) {
		/* pcap extended header */
		printf ("Extended IP header contains mask: 0x%02x\n", co.ip_mask); /* XXX */
		printf ("Extended TCP header contains mask: 0x%04x\n", co.tcp_mask); /* XXX */
		printf ("Extended UDP header contains mask: 0x%02x\n", co.udp_mask); /* XXX */
		printf ("Extended header contains offset: %i\n", co.rm_offset); /* XXX */
		printf ("Extended header contains filter: %s\n", filter); /* XXX */
	}


	/* open output file */
	if ((foutname[0] == '-' && foutname[1] == '\0') || (foutname[0] == '\0')) {
		lfout = lfdopen (STDOUT_FILENO, 8192);
	} else {
		lfout = lfopen (foutname, 8192);
		if (lfout == NULL) {
			fprintf (stderr, "Error: cannot open file %s\n", foutname);
			fclose (fin);
			exit (1);
		}
	}


	/* check if the file is compressed or not */
	if (filehdr.linktype == DLT_COMPRESSED) {
		uncompress_file (fin, lfout, &co);
	} else {
		compress_file (fin, lfout, &filehdr, swapped);
	}

	fclose (fin);
	lfclose (lfout);
	exit (0);
}




/*
 * uncompress_file
 *
 * Uncompresses the stream fin into foutname
 *
 * Inputs:
 *	- fin: the compressed input stream
 *	- lfout: the uncompressed output stream
 *	- co: compression parameters
 *
 * Output:
 *	- return: 0 if ok, <0 if there was any problem
 *
 */
int uncompress_file (FILE *fin, lFILE *lfout, co_t *co)
{
	codec_t *codec;
	int size;
	u_char compressed_buffer[MAX_COMPRESSED_LENGTH];
	u_char buffer[MAXDATABUFFER];
	struct pcap_pkthdr pkthdr;
	int result;


	/* create and initialize codec */
	codec = create_codec();


	/* write the new header */
	if (pktd_write_header (lfileno(lfout), 40, DLT_RAW) < 0) {
		fprintf (stderr, "Error: cannot write header in file %s\n", foutname);
		return -1;
	}


/*
 * every time you seek the rm_offset, you *must* initialize the codec
	(void)fseek (fin, co->rm_offset, SEEK_CUR);
	init_codec (codec);
 */

	/* parse traces */
	while (1) {
		/* read the trace length */
		size = TCPDUMP_PACKET_HEADER_LENGTH_COMPRESSED;
		result = fread (compressed_buffer, 1, size, fin);
		if (result != size) {
			if ((result == 0) && (feof (fin))) {
				break;
			}
			fprintf (stderr, "Error: fread'ing file %s\n", finname);
			return -1;
		}
		size = (u_int8_t)(compressed_buffer[0]);


		/* look for escaped packets */
		if (size == COMPRESSION_INIT_CODEC) {
			/* codec initialization requested */
			init_codec (codec); 
			continue;
      
		} else if (size == COMPRESSION_PADDING) {
			/* padding (empty) trace */
			continue;
		}


		/* get the rest of the compressed packet */
		result = fread (compressed_buffer+TCPDUMP_PACKET_HEADER_LENGTH_COMPRESSED, 
				1, size-TCPDUMP_PACKET_HEADER_LENGTH_COMPRESSED, fin);
		if (result != (size-TCPDUMP_PACKET_HEADER_LENGTH_COMPRESSED)) {
			if ((size == 0) && (feof (fin))) {
				break;
			}
			fprintf (stderr, "Error: freading file %s (%i)\n", finname, size);
			return -1;
		}


		/* decode the packet */
		size = decode_trace (codec, compressed_buffer, &pkthdr, buffer);
		if (size < 0) {
			fprintf (stderr, "Error: decoding trace\n");
			return -1;
		}


		/* write the uncompressed packet */
		/*
		result = fwrite(buffer, 1, size, fout);
		*/
		result = lfwrite(lfout, buffer, size);
		if (result != size) {
			fprintf (stderr, "Error: fwriting file %s\n", foutname);
			return -1;
		}
	}


	return 0;
}




/*
 * compress_file
 *
 * Compresses the stream fin into foutname. This code is shamelessly
 * copied from libpcap's savefile.c:sf_next_packet()
 *
 * Inputs:
 *	- fin: the uncompressed input stream
 *	- lfout: the compressed output stream
 *	- filehdr: the file header
 *	- swapped: whether the packet order is swapped compared to the host order
 *
 * Output:
 *	- return: 0 if ok, <0 if there was any problem
 *
 */
int compress_file (FILE *fin, lFILE *lfout, struct pcap_file_header *filehdr, 
		int swapped)
{
	codec_t *codec;
	int size;
	int hdr_size;
	u_char buffer[MAXDATABUFFER];
	struct pcap_pkthdr pkthdr;
	int result;
	u_char *comp_pkt;
	int comp_len;
	u_int32_t bytes_written;
	co_t co;
	int paddings;


	/* get header size */
	hdr_size = pktd_get_hdr_size (filehdr->linktype);


	/* create and initialize codec */
	codec = create_codec();

	/* get compression parameters */
	co.rm_offset = DEFAULT_PKTD_COMPRESSION_RESTART_MARKER;
	co.ip_mask = DEFAULT_PKTD_COMPRESSION_IP_MASK;
	co.tcp_mask = DEFAULT_PKTD_COMPRESSION_TCP_MASK;
	co.udp_mask = DEFAULT_PKTD_COMPRESSION_UDP_MASK;


	/* write the new extended pcap header */
	if (pktd_lfwrite_ext_header (lfout, 40, DLT_COMPRESSED, &co, NULL) < 0) {
		fprintf (stderr, "Error: cannot write header in file %s\n", foutname);
		return -1;
	}


	bytes_written = 0;

	while (1) {

		/* read the pcap header */
		size = TCPDUMP_PACKET_HEADER_LENGTH;
		result = fread (&pkthdr, 1, size, fin);
		if (result != size) {
			if ((result == 0) && (feof (fin))) {
				break;
			}
			fprintf (stderr, "Error: fread'ing file %s\n", finname);
			return -1;
		}

		/* encode_trace requires pkthdr in host order */
		if (swapped) {
			pktd_swap_pkthdr (&pkthdr);
		}

		/* The caplen and len fields were interchanged at version 2.3,
		 * in order to match the bpf header layout.  But unfortunately
		 * some files were written with version 2.3 in their headers
		 * but without the interchanged fields */
		if (filehdr->version_minor < 3 ||
				(filehdr->version_minor == 3 && pkthdr.caplen > pkthdr.len)) {
			int t = pkthdr.caplen;
			pkthdr.caplen = pkthdr.len;
			pkthdr.len = t;
		}


		/* read the packet itself */
		size = pkthdr.caplen;
		result = fread (buffer, 1, size, fin);
		if (result != size) {
			if ((result == 0) && (feof (fin))) {
				break;
			}
			fprintf (stderr, "Error: freading file %s\n", finname);
			return -1;
		}

		/* encode_trace requires packet in network order, so no swap is needed */

		/* encode the packet */
		encode_trace (codec, &co, &pkthdr, buffer, pkthdr.caplen, hdr_size, 
				&comp_pkt, &comp_len);

		/* introduce restart markers if needed */
		if (co.rm_offset != 0) {
			paddings = need_restart_markers (&co, lfout, comp_len, bytes_written, 
					codec);
			if (paddings < 0) {
				return -1;
			} else if (paddings > 0) {
				bytes_written += paddings;
				/* there was a codec initialization => must reencode packet */
				encode_trace (codec, &co, &pkthdr, buffer, pkthdr.caplen, hdr_size, 
						&comp_pkt, &comp_len);
			}
		}

		/* write compressed packet to file */
		if (lfwrite (lfout, comp_pkt, comp_len) < comp_len) {
			return -1;
		}
	}

	return 0;
}




/*
 * usage
 *
 * A simple usage method
 *
 * Inputs:
 *	- argv: arguments
 *
 * Outputs:
 *
 */
void usage (char **argv)
{
	fprintf (stderr, "Usage: %s [options]\n", *argv);
	fprintf (stderr, "  -h\t\tShow this information\n");
	fprintf (stderr, "  -V\t\tDisplay pktd version number only\n");
	fprintf (stderr, "  -r [file]\tChoose file to read\n");
	fprintf (stderr, "  -w [file]\tChoose file to write\n");
}




/*
 * parse_args
 *
 * Parse command line for options
 *
 * Inputs:
 *	- argc: argument counter
 *	- argv: arguments
 *
 * Outputs:
 *
 */
void parse_args (int argc, char **argv)
{
	int arg;
	extern char *optarg;
	extern int optind;
	extern int opterr;

	/* the arguments to options must be separated by white-space. */
	opterr = 0;
	while ((arg = getopt(argc, argv, "r:w:Vh?")) != -1) {
		switch (arg) {
			case 'r':
				strcpy (finname, optarg);
				break;

			case 'w':
				strcpy (foutname, optarg);
				break;

			case 'V':
				/* dump version number and exit */
				fprintf (stderr, "%s for pktd %s\n", argv[0], pktd_version);
				exit(0);
				break;

			case 'h':
			default:
				usage (argv);
				exit(1);
				break;
		}
	}

#if 0
	if ((finname[0] == '\0') || (foutname[0] == '\0')) {
		usage (argv);
		exit(1);
	}
#endif

	return;
}




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


struct timeval ts_add (const struct timeval *ts, const long amount);
long ts_sub (const struct timeval *tsa, const struct timeval *tsb);






codec_t *init_codec ()
{
	codec_t *codec;
	int cid;

	codec = (codec_t *) malloc (sizeof(codec_t));

	 
	codec->last_pcap_hdr.ts.tv_sec = 0;
	codec->last_pcap_hdr.ts.tv_usec = 0;
	codec->last_pcap_hdr.caplen = 0;
	codec->last_pcap_hdr.len = 0;

	 
 
	for (cid=0; cid< (4  + 4  + 1) ; cid++) {
		bzero(codec->last_ip_hdr[cid], 40);
		codec->last_ip_hdr[cid][0] = 0x45;
		bzero(codec->last_nl_hdr[cid], 40);
		codec->lru_time[cid] = 0;
	}

	codec->current_time = 0;

	return codec;
}

















int get_cache_conn_id (codec_t *codec, const u_char *ip_hdr)
{
	int cid, oldest_cid;
	u_char *nl_hdr;

	nl_hdr = (u_char *)ip_hdr + (((*(u_int8_t *)(ip_hdr+0)) & 0x0f) << 2);
	if (codec->lru_time[cid] == 0xffffffff) {
		codec->current_time = 0;
		for (cid=0; cid< (4  + 4  + 1) ; cid++) {
			codec->lru_time[cid] = 0;
		}
	} else {
		codec->current_time++;
	}

	switch (*(u_int8_t *)(ip_hdr+9)) {
		case 17 :
			oldest_cid = 0;
			for (cid=0; cid < 4 ; cid++) {
				if (((*(u_int32_t *)( ip_hdr +12) != *(u_int32_t *)(codec->last_ip_hdr[  cid ]+12)) && (*(u_int32_t *)( ip_hdr +16) != *(u_int32_t *)(codec->last_ip_hdr[  cid ]+16)) && (*(u_int16_t *)(  nl_hdr +0) != *(u_int16_t *)(codec->last_nl_hdr[  cid ]+0)) && (*(u_int16_t *)(  nl_hdr +2) != *(u_int16_t *)(codec->last_nl_hdr[  cid ]+2))) ) {
					codec->lru_time[cid] = codec->current_time;
					return cid;
				}
				oldest_cid = (codec->lru_time[ oldest_cid ] <= codec->lru_time[  cid ]) ?  oldest_cid  :   cid  ;
				cid++;
			}
			break;

		case 6 :
			oldest_cid = 4 ;
			for (cid= 4 ; cid < ((4  + 4  + 1) -1); cid++) {
				if (((*(u_int32_t *)( ip_hdr +12) != *(u_int32_t *)(codec->last_ip_hdr[  cid ]+12)) && (*(u_int32_t *)( ip_hdr +16) != *(u_int32_t *)(codec->last_ip_hdr[  cid ]+16)) && (*(u_int16_t *)(  nl_hdr +0) != *(u_int16_t *)(codec->last_nl_hdr[  cid ]+0)) && (*(u_int16_t *)(  nl_hdr +2) != *(u_int16_t *)(codec->last_nl_hdr[  cid ]+2))) ) {
					codec->lru_time[cid] = codec->current_time;
					return cid;
				}
				oldest_cid = (codec->lru_time[ oldest_cid ] <= codec->lru_time[  cid ]) ?  oldest_cid  :   cid  ;
				cid++;
			}
			break;

		default:
			break;
	}

	return ((4  + 4  + 1)  - 1);
}




int encode_trace (codec_t *codec, lFILE *fp, 
		const struct pcap_pkthdr *pcap_hdr, const u_char *pkt, u_int caplen, 
		int datalink_hdr_length)
{
	long ts_diff;
	u_int8_t i, ii;
	u_char packet[99];
	u_char *ip_hdr;
	int cid;
	u_int8_t ip_hdr_mask;
	u_int16_t ip_hdr_length, ip_total_length;
	u_int16_t ip_id_diff;
	u_int8_t transport_protocol;
	u_int16_t ip_ck_sum;
	int ip_fragment;
	u_int8_t udp_hdr_mask;
	u_char *udp_hdr;
	u_int16_t udp_ck_sum;


	 
	i = 1;


	 
	ts_diff = ts_sub (&(pcap_hdr->ts), &(codec->last_pcap_hdr.ts));
	if ((0 <= ts_diff) && (ts_diff <= 253)) {
		 
		*(u_int8_t *)(packet+i) = (u_int8_t)ts_diff;
		i++;
		
	} else if ((0 <= ts_diff) && (ts_diff <= 65535)) {
		 
		*(u_char *)(packet+i) = 0xff;
		i++;
		*(u_int16_t *)(packet+i) = __extension__ ({ register u_short __X = ( (u_int16_t)ts_diff ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
		i += 2;

	} else {
		 
		*(u_char *)(packet+i) = 0xfe;
		i++;
		*(long *)(packet+i) = __extension__ ({ register u_long __X = ( (long)pcap_hdr->ts.tv_sec ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
		i += 4;
		*(long *)(packet+i) = __extension__ ({ register u_long __X = ( (long)pcap_hdr->ts.tv_usec ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
		i += 4;
	}
	codec->last_pcap_hdr = *pcap_hdr;


	 
	pkt += datalink_hdr_length;


	 
	ip_hdr_mask = 0;
	ip_hdr = (u_char *)pkt;
	cid = get_cache_conn_id (codec, ip_hdr);
	ii = i++;

	 
	if (*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+0)) {
		ip_hdr_mask |= 0x80;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	ip_hdr_length = ((*(u_int8_t *)pkt) & 0x0f) << 2;
	pkt += 2;

	 
	if (*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+2)) {
		ip_hdr_mask |= 0x40;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	ip_total_length = __extension__ ({ register u_short __X = ( *(u_int16_t *)pkt ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
	pkt += 2;

	 
	if (*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+4)) {
		ip_hdr_mask |= 0x20;
		ip_id_diff = __extension__ ({ register u_short __X = ( *(u_int16_t *)pkt ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; })  - 
				__extension__ ({ register u_short __X = ( *(u_int16_t *)(codec->last_ip_hdr[cid]+4) ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
		if (ip_id_diff <= 256) {
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

	 
	ip_fragment = 0;
	if (*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+6)) {
		ip_hdr_mask |= 0x10;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	if ((__extension__ ({ register u_short __X = ( *(u_int16_t *)pkt ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; })  & 0x1fff) != 0)  {
		 
		ip_fragment = 1;
	}
	pkt += 2;

	 
	if (*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_ip_hdr[cid]+8)) {
		ip_hdr_mask |= 0x08;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	transport_protocol = *(u_int8_t *)(pkt+1);
	pkt += 2;

	 
	{ int j; register u_int32_t sum; sum = 0; for (j = 0; j <   ip_hdr_length ; j = j + 2) { if (j != 10) { sum += (u_int32_t)*(u_int16_t *)( ip_hdr +j);	} } while ((sum >> 16) != 0) { sum = (sum & 0xffff) + (sum >> 16); }   ip_ck_sum  = (u_int16_t)(~sum & 0xffff); } ;
	if (*(u_int16_t *)pkt != ip_ck_sum) {
		printf ("BAD IP CHECKSUM: %x vs. %x\n", ip_ck_sum, *(u_int16_t *)pkt);  
		ip_hdr_mask |= 0x04;
		*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
		i += 2;
	}
	pkt += 2;

	 
	if (*(u_int32_t *)pkt != *(u_int32_t *)(codec->last_ip_hdr[cid]+12)) {
		ip_hdr_mask |= 0x02;
		*(u_int32_t *)(packet+i) = *(u_int32_t *)pkt;
		i += 4;
	}
	pkt += 4;

	 
	if (*(u_int32_t *)pkt != *(u_int32_t *)(codec->last_ip_hdr[cid]+16)) {
		ip_hdr_mask |= 0x01;
		*(u_int32_t *)(packet+i) = *(u_int32_t *)pkt;
		i += 4;
	}
	pkt += 4;

	 
	if (ip_hdr_length > 20) {
		bcopy (pkt, packet, ip_hdr_length - 20);
		i += ip_hdr_length - 20;
		pkt += ip_hdr_length - 20;
	}

	 
	packet[ii] = ip_hdr_mask;

	bcopy (ip_hdr, codec->last_ip_hdr[cid], 20);


	 
	if (ip_fragment == 1) {
		 


	} else {
		switch (transport_protocol) {
			case 17 :
				 
				udp_hdr_mask = (cid&0x07)<<4;
				ii = i++;
				udp_hdr = (u_char *)pkt;

				 
				if (*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_nl_hdr[cid]+0)) {
					udp_hdr_mask |= 0x08;
					*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
					i += 2;
				}
				pkt += 2;

				 
				if (*(u_int16_t *)pkt != *(u_int16_t *)(codec->last_nl_hdr[cid]+2)) {
					udp_hdr_mask |= 0x04;
					*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
					i += 2;
				}
				pkt += 2;

				 
				if (__extension__ ({ register u_short __X = ( *(u_int16_t *)pkt ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; })  != (ip_total_length - ip_hdr_length)) {
					udp_hdr_mask |= 0x02;
					*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
					i += 2;
				}
				pkt += 2;

				 
				 



				 

				{ register u_int32_t sum; sum = 0; sum += (u_int32_t)*(u_int8_t *)( ip_hdr +9); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +12); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +14); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +16); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +18); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +4); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +0); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +2); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +4); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +6); while ((sum >> 16) != 0) { sum = (sum & 0xffff) + (sum >> 16); }   udp_ck_sum  = (u_int16_t)(~sum & 0xffff); } ;
udp_ck_sum = *(u_int16_t *)pkt;  
				if (*(u_int16_t *)pkt != udp_ck_sum) {
		printf ("BAD UDP CHECKSUM: %x vs. %x\n", udp_ck_sum, *(u_int16_t *)pkt);  
					udp_hdr_mask |= 0x01;
					*(u_int16_t *)(packet+i) = *(u_int16_t *)pkt;
					i += 2;
				}
				pkt += 2;

				 
				packet[ii] = udp_hdr_mask;

				bcopy (udp_hdr, codec->last_nl_hdr[cid], 8);

				break;

			case 6 :
				printf ("TCP: not yet\n");
				break;

			case 1 :
				printf ("ICMP: not yet\n");
				break;

			default:
				break;
		}
	}


	 
	*(u_int8_t *)(packet+0) = (u_int8_t)i;


	 
	if (lfwrite (fp, packet, i) < i) {
		return -1;
	}

	return 0;
}




int decode_trace (codec_t *codec, u_char *compressed_buffer, 
		struct pcap_pkthdr *pcap_hdr, u_char *pkt)
{
	int i;
	int offset, len_offset;
	long ts_diff;
	u_int8_t ip_hdr_mask;
	u_char *ip_hdr;
	u_int16_t ip_hdr_length, ip_total_length;
	int ip_fragment;
	int transport_protocol;
	u_int16_t ip_ck_sum;
	int cid;
	u_int8_t udp_hdr_mask;
	u_char *udp_hdr;
	u_int16_t udp_ck_sum;


	i = 1;
	offset = 0;

	 
	switch (*(u_char *)(compressed_buffer+i)) {
		case 0xff:
			 
			i++;
			ts_diff = (long)__extension__ ({ register u_short __X = ( *(u_int16_t *)(compressed_buffer+i) ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
			i += 2;
			pcap_hdr->ts = ts_add (&(codec->last_pcap_hdr.ts), ts_diff);
			break;

		case 0xfe:
			 
			i++;
			pcap_hdr->ts.tv_sec = __extension__ ({ register u_long __X = ( *(long *)(compressed_buffer+i) ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
			i += 4;
			pcap_hdr->ts.tv_usec = __extension__ ({ register u_long __X = ( *(long *)(compressed_buffer+i) ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
			i += 4;
			break;

		default:
			 
			ts_diff = (long)(*(u_int8_t *)(compressed_buffer+i));
			pcap_hdr->ts = ts_add (&(codec->last_pcap_hdr.ts), ts_diff);
			i++;
			break;
	}
	*(long *)(pkt+offset) = __extension__ ({ register u_long __X = ( pcap_hdr->ts.tv_sec ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
	offset += 4;
	*(long *)(pkt+offset) = __extension__ ({ register u_long __X = ( pcap_hdr->ts.tv_usec ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
	offset += 4;
	len_offset = offset;
	offset += 8;

	bcopy (pcap_hdr, &codec->last_pcap_hdr, 16);


	 
	ip_hdr_mask = *(u_int8_t *)(compressed_buffer+i);
	{ int index = 0; index += ((((  ip_hdr_mask   &   0x80 ) == 0) ? 0 : 1) ) ? 2 : 0; index += ((((  ip_hdr_mask   &   0x40 ) == 0) ? 0 : 1) ) ? 2 : 0; if ((((  ip_hdr_mask   &   0x20 ) == 0) ? 0 : 1) ) { if ((*(u_int8_t *)(  compressed_buffer +index) == 0) { index += 2; } else { index += 1; } } index += ((((  ip_hdr_mask   &   0x10 ) == 0) ? 0 : 1) ) ? 2 : 0; index += ((((  ip_hdr_mask   &   0x08 ) == 0) ? 0 : 1) ) ? 2 : 0; index += ((((  ip_hdr_mask   &   0x04 ) == 0) ? 0 : 1) ) ? 2 : 0; index += ((((  ip_hdr_mask   &   0x02 ) == 0) ? 0 : 1) ) ? 4 : 0; index += ((((  ip_hdr_mask   &   0x01 ) == 0) ? 0 : 1) ) ? 4 : 0;   cid  = ((*(u_int8_t *)(  compressed_buffer +index)) & 0x70) >> 4; } ;
	i++;
	ip_hdr = pkt+offset;


	 
	if (((( ip_hdr_mask  &   0x80 ) == 0) ? 0 : 1) ) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+0);
	}
	ip_hdr_length = ((*(u_int8_t *)(pkt+offset)) & 0x0f) << 2;
	offset += 2;

	 
	if (((( ip_hdr_mask  &   0x40 ) == 0) ? 0 : 1) ) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+2);
	}
	ip_total_length = __extension__ ({ register u_short __X = ( *(u_int16_t *)(pkt+offset) ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
	offset += 2;

	 
	if (((( ip_hdr_mask  &   0x20 ) == 0) ? 0 : 1) ) {
		if (*(u_int8_t *)(compressed_buffer+i) == 0) {
			i++;
			*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
			i += 2;
		} else {
			*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+4) + 
					(u_int16_t)(*(u_int8_t *)(compressed_buffer+i));
			i++;
		}
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+4);
	}
	offset += 2;

	 
	ip_fragment = 0;
	if (((( ip_hdr_mask  &   0x10 ) == 0) ? 0 : 1) ) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+6);
	}
  if ((__extension__ ({ register u_short __X = ( *(u_int16_t *)(pkt+offset) ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; })  & 0x1fff) != 0)  {
     
    ip_fragment = 1;
  }
	offset += 2;

	 
	if (((( ip_hdr_mask  &   0x08 ) == 0) ? 0 : 1) ) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_ip_hdr[cid]+8);
	}
	transport_protocol = *(u_int8_t *)(pkt+offset+1);
	offset += 2;

	 
	if (((( ip_hdr_mask  &   0x04 ) == 0) ? 0 : 1) ) {
		*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
		i += 2;
	} else {
		{ int j; register u_int32_t sum; sum = 0; for (j = 0; j <   ip_hdr_length ; j = j + 2) { if (j != 10) { sum += (u_int32_t)*(u_int16_t *)( ip_hdr +j);	} } while ((sum >> 16) != 0) { sum = (sum & 0xffff) + (sum >> 16); }   ip_ck_sum  = (u_int16_t)(~sum & 0xffff); } ;
		*(u_int16_t *)(pkt+offset) = __extension__ ({ register u_short __X = ( ip_ck_sum ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
	}
	offset += 2;

	 
	if (((( ip_hdr_mask  &   0x02 ) == 0) ? 0 : 1) ) {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(compressed_buffer+i);
		i += 4;
	} else {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(codec->last_ip_hdr[cid]+12);
	}
	offset += 4;

	 
	if (((( ip_hdr_mask  &   0x01 ) == 0) ? 0 : 1) ) {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(compressed_buffer+i);
		i += 4;
	} else {
		*(u_int32_t *)(pkt+offset) = *(u_int32_t *)(codec->last_ip_hdr[cid]+16);
	}
	offset += 4;

	 
	if (ip_hdr_length > 20) {
		bcopy (compressed_buffer+i, pkt+offset, ip_hdr_length - 20);
		i += ip_hdr_length - 20;
		offset += ip_hdr_length - 20;
	}

	bcopy (ip_hdr, codec->last_ip_hdr[cid], ip_hdr_length);

 










	 
	if (ip_fragment == 1) {
		 


	} else {

		switch (transport_protocol) {
			case 17 :
				 
				udp_hdr_mask = *(u_int8_t *)(compressed_buffer+i);
				i++;
				udp_hdr = pkt+offset;

				 
				if (((( udp_hdr_mask  &   0x80 ) == 0) ? 0 : 1) ) {
					*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
					i += 2;
				} else {
					*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_nl_hdr[cid]+0);
				}
				offset += 2;

				 
				if (((( udp_hdr_mask  &   0x40 ) == 0) ? 0 : 1) ) {
					*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
					i += 2;
				} else {
					*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(codec->last_nl_hdr[cid]+2);
				}
				offset += 2;

				 
				if (((( udp_hdr_mask  &   0x20 ) == 0) ? 0 : 1) ) {
					*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
					i += 2;
				} else {
					*(u_int16_t *)(pkt+offset) = __extension__ ({ register u_short __X = ( (u_int16_t)(ip_total_length - 
							ip_hdr_length) ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
				}
				offset += 2;

				 
				if (((( udp_hdr_mask  &   0x10 ) == 0) ? 0 : 1) ) {
					*(u_int16_t *)(pkt+offset) = *(u_int16_t *)(compressed_buffer+i);
					i += 2;
				} else {
					{ register u_int32_t sum; sum = 0; sum += (u_int32_t)*(u_int8_t *)( ip_hdr +9); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +12); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +14); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +16); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +18); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +4); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +0); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +2); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +4); sum += (u_int32_t)*(u_int16_t *)( ip_hdr +  ip_hdr_length +6); while ((sum >> 16) != 0) { sum = (sum & 0xffff) + (sum >> 16); }   udp_ck_sum  = (u_int16_t)(~sum & 0xffff); } ;
					*(u_int16_t *)(pkt+offset) = __extension__ ({ register u_short __X = ( udp_ck_sum ); __asm ("xchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
				}
				offset += 2;

				bcopy (udp_hdr, codec->last_nl_hdr[cid], 8);
				break;

			case 6 :
				printf ("TCP: not yet\n");
				break;

			case 1 :
				printf ("ICMP: not yet\n");
				break;

			default:
				break;
		}

	}

	 
	pcap_hdr->caplen = offset;
	pcap_hdr->len = ip_total_length;
	*(long *)(pkt+len_offset) = __extension__ ({ register u_long __X = ( pcap_hdr->caplen ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
	len_offset += 4;
	*(long *)(pkt+len_offset) = __extension__ ({ register u_long __X = ( pcap_hdr->len ); __asm ("xchgb %h1, %b1\n\trorl $16, %1\n\txchgb %h1, %b1" : "=q" (__X) : "0" (__X)); __X; }) ;
	len_offset += 4;

	return 0;
}



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


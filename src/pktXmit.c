/*
 * Covert Channel client/server
 *
 * $Id: pktXmit.c,v 1.6 2006/08/03 19:49:49 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>

#include "pktXmit.h"

eth_t *
initPktXmit (const char *device)
{
  /* open a link-layer interface, bypassing kernel bits */
  eth_t *e = eth_open (device);
  if (e == (eth_t *) NULL)
    {
      fprintf (stderr, "%s(%d) eth_open ", __FILE__, __LINE__);
      perror (device);
      exit (EX_USAGE);
    }

  return e;
}

/* Calculate the checksum of an IP packet */
unsigned short
in_cksum (unsigned short *addr, int len)
{
  /* taken from UNPv1, figure 25.14 on p672.  Page 671 notes that
     "[t]his algorithm is used for the IPv4, ICMPv4, IGMPv5, ICMPv6,
     UDP, and TCP checksums." */

  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  /* Our algorithm is simple, using a 43 bit accumulator (sum), we add
     sequential 16 bit words to it, and at the end, fold back all the
     carry bits from the top 16 bits into the lower 16 bits.  */

  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */

  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */

  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* truncate to 16 bits */

  return answer;
}

unsigned short
tcp_cksum (struct ip *ipPkt, struct tcphdr *tcpPkt, const size_t dataLen)
{
/*   static struct pseudoHeader *ph = (struct pseudoHeader *) NULL;  */

  /* allocate memory if necessary */ 
/*    if (ph == (struct pseudoHeader *) NULL)  */
/*      {  */
/*        ph = (struct pseudoHeader *) malloc (TCPBUFSIZE);  */
/*        if (ph == (struct pseudoHeader *) NULL)  */
/*  	{  */
/*  	  fprintf (stderr, "%s(%d) ", __FILE__, __LINE__);  */
/*  	  perror ("malloc(TCPBUFSIZE)");  */
/*  	  exit (EX_OSERR);  */
/*  	}  */
/*      }  */
   
   /* checksum field should be zero before calculation */ 
/*    tcpPkt->th_sum = 0; */

   /* fill out pseudoheader */ 
/*    ph->s_addr = ipPkt->ip_src.s_addr;  */
/*    ph->d_addr = ipPkt->ip_dst.s_addr; */
/*    ph->zero = 0; */
/*    ph->protocol = IPPROTO_TCP;  */
/*    ph->tcpLength = htons(sizeof (struct tcphdr) + dataLen);  */
/*    memcpy (&ph->tcpPkt, tcpPkt, sizeof (struct tcphdr) + dataLen);  */

   /* calculate checksum */ 
/*    return tcpPkt->th_sum =  */
/*      in_cksum ((unsigned short *) ph,  */
/*  	      sizeof (struct pseudoHeader) + dataLen);  */

  /* TODO: get TCP checksums working */
  return tcpPkt->th_sum = 0;
}

unsigned short
ip_cksum (struct ip *ipPkt)
{
  /* checksum field should be zero before calculation */
  ipPkt->ip_sum = 0;

  ipPkt->ip_sum =
    htons (in_cksum ((unsigned short *) ipPkt, IPHLTOBYTES (ipPkt->ip_hl)));

  return ipPkt->ip_sum;
}

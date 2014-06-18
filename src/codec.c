/*
 * Covert Channel client/server
 *
 * $Id: codec.c,v 1.6 2006/08/03 00:47:30 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include "codec.h"

int
encodeOne (struct ip *ipPkt, u_char nextByte, u_char pseudoKey,
	   u_char randNum)
{
  /* 
   * ip->id = identification (half rand, half secret ^ rand)
   *
   * length = actual packet length
   * 
   * offset = length - data
   */

  u_char *idChar = (u_char *) (&ipPkt->ip_id);

  /* set the ID to show who we are */
  idChar[0] = randNum;
  idChar[1] = idChar[0] ^ pseudoKey;

  /* the IP length must be greater than the data to send, and less
     than 0x1fff (8191) to fit. */
  if ((ipPkt->ip_len < nextByte) || (ipPkt->ip_len > IP_OFFMASK))
    {
      printf ("Skipping packet: length (%hi) must be data (%i) < len < %hi\n",
	      ipPkt->ip_len, nextByte, IP_OFFMASK);
      return FALSE;
    }

  /* set offset to show data then set more fragments bit without
     discarding original data */
  ipPkt->ip_off = (ipPkt->ip_len - nextByte) + IP_MF;

  return TRUE;
}

int
isOneEncoded (struct ip *ipPkt, u_char pseudoKey)
{
  u_char *idChar = (u_char *) (&ipPkt->ip_id);

  /* TODO: also should have IP_MF set */

  /* is this packet encoded using method one? */
  if ((idChar[1] ^ idChar[0]) == pseudoKey)
    return TRUE;

  return FALSE;
}

u_char
decodeOne (struct ip * ipPkt)
{
  /* assume that this is a real OneEncoded packet */

  return (ipPkt->ip_len - (ipPkt->ip_off + IP_MF));
}

int
encodeTwo (struct ip *ipPkt, struct tcphdr *tcpPkt,
	   u_char nextByte, char *pseudoKey, uint32_t randNum)
{
  /*
   * - random 4 bytes in TCP SEQ
   * - 4 byte secret ^ TCP SEQ in TCP ACK
   * - More frags bit set in IP header
   * - Frag offset set to 0 to make TCP header legal
   * - Data stored in frags, IPID, TCPWindow, or TCPUrgentPointer,
   *   based on the modulo of the random number
   */

  /* set the sequence and ack numbers to show who we are */
  tcpPkt->th_seq = randNum;
  tcpPkt->th_ack = (tcpPkt->th_seq ^ *(tcp_seq *) & pseudoKey); 

  /* set offset to zero and set more fragments bit */
  ipPkt->ip_off = IP_MF;

  /* choose where to hide the data based on the random number */
  switch (randNum % TE_MAX)
    {
    case TE_ID:
      ipPkt->ip_id = randNum ^ nextByte;
      break;
    case TE_TCPWIN:
      tcpPkt->th_win = randNum ^ nextByte;
      break;
    case TE_TCPURG:
      tcpPkt->th_urp = randNum ^ nextByte;
      break;
    default:
      fprintf (stderr, "%s(%d) switch/case gone bad", __FILE__, __LINE__);
      exit (EX_UNAVAILABLE);
    }

  return TRUE;			/* yes, please transmit */
}

int
isTwoEncoded (struct ip *ipPkt, struct tcphdr *tcpPkt, char *pseudoKey)
{
  /* TODO: also should have IP_MF set */

  /* is this packet encoded using method two? */
  if ((tcpPkt->th_seq ^ tcpPkt->th_ack) == *(tcp_seq *) & pseudoKey)
    return TRUE;

  return FALSE;
}

u_char
decodeTwo (struct ip * ipPkt, struct tcphdr * tcpPkt, char *pseudoKey)
{
  /* assume that this is a real TwoEncoded packet */

  uint32_t randNum = tcpPkt->th_seq;

  /* choose where to hide the data based on the random number */
  switch (randNum % TE_MAX)
    {
    case TE_ID:
      return ipPkt->ip_id ^ randNum;
      break;
    case TE_TCPWIN:
      /* TODO: this shouldn't point past the end of the packet */
      return tcpPkt->th_win ^ randNum;
      break;
    case TE_TCPURG:
      return tcpPkt->th_urp ^ randNum;
      break;
    default:
      fprintf (stderr, "%s(%d) switch/case gone bad", __FILE__, __LINE__);
      exit (EX_UNAVAILABLE);
    }

  return (ipPkt->ip_len - (ipPkt->ip_off + IP_MF));
}

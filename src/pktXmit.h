/*
 * Covert Channel client/server
 *
 * $Id: pktXmit.h,v 1.5 2006/08/03 19:49:49 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#ifndef __PKTXMIT_H
#define __PKTXMIT_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

/* The libnet file has all kinds of compilation warnings that I'd rather
 * not see.  Sadly, GCC's pragma disables warnings for this whole file.
 * Be wary.
 */
#if defined __GNUC__
#pragma GCC system_header
#elif defined __SUNPRO_CC
#pragma disable_warn
#elif defined _MSC_VER
#pragma warning(push, 1)
#endif

#include "dnet.h"

#if defined __SUNPRO_CC
#pragma enable_warn
#elif defined _MSC_VER
#pragma warning(pop)
#endif

#define IPHLTOBYTES(HL) (HL << 2)
#define TCPOFFTOBYTES(OFF) (OFF << 2)

/* pseudoHeader for calculating TCP checksum as per RFC 793 */
   
struct pseudoHeader 
{ 
  uint32_t s_addr;
  uint32_t d_addr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t tcpLength;
  struct tcphdr tcpPkt;
};

 /*struct pseudoHeader 
{ 
  unsigned long s_addr;
  unsigned long d_addr;
  char zero;
  unsigned char protocol;
  unsigned short tcpLength;
  struct tcphdr tcpPkt;
  };*/

/* size of a packet for calculating checksum */
/* I'm cheating ... a packet shouldn't be this big, but it can be */
#define TCPBUFSIZE (sizeof (struct pseudoHeader) + 2000)

eth_t *initPktXmit (const char *);
unsigned short tcp_cksum (struct ip *, struct tcphdr *, const size_t);
unsigned short ip_cksum (struct ip *);

#endif /* __PKTXMIT_H */

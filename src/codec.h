/*
 * Covert Channel client/server
 *
 * $Id: codec.h,v 1.5 2006/08/02 23:13:19 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#ifndef __CODEC_H
#define __CODEC_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

#define TRUE (0==0)
#define FALSE (!TRUE)

#define PSEUDOKEYLENBYTES (sizeof (uint32_t))	/* worst case scenario */

#define TE_ID (0)		/* data stored in ID fields */
#define TE_TCPWIN (1)		/* data stored in TCP Window */
#define TE_TCPURG (2)		/* data stored in TCP Urgent Pointer */
#define TE_MAX (3)		/* maximum number of TwoEncodings */

int encodeOne (struct ip *, u_char nextByte, u_char pseudoKey,
	       u_char randNum);
int isOneEncoded (struct ip *ipPkt, u_char pseudoKey);
u_char decodeOne (struct ip *ipPkt);

int encodeTwo (struct ip *ipPkt, struct tcphdr *tcpPkt,
	       u_char nextByte, char *pseudoKey, uint32_t randNum);
int isTwoEncoded (struct ip *ipPkt, struct tcphdr *tcpPkt, char *pseudoKey);
u_char decodeTwo (struct ip *ipPkt, struct tcphdr *tcpPkt, char *pseudoKey);

#endif /* __CODEC_H */

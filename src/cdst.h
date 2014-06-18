/*
 * Covert Channel client/server
 *
 * $Id: cdst.h,v 1.5 2006/08/02 23:13:19 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#ifndef __CDST_H
#define __CDST_H

#include <stdio.h>
#include <sysexits.h>
#include <stdlib.h>
#include <sys/types.h>

#include <netinet/if_ether.h>	/* for struct ether_header */
#include <netinet/ip.h>		/* for struct ip */
#include <netinet/tcp.h>	/* for struct tcphdr */
#include <net/ethernet.h>	/* for ETHERTYPEs */
#include <netinet/in.h>		/* for IPPROTOs */
#include <arpa/inet.h>		/* for htons/ntohl/etc. */

#include "dllist.h"

#include "pktRecv.h"
#include "pktXmit.h"
#include "util.h"
#include "codec.h"

/* global constants */

#define TRUE (0==0)
#define FALSE (!TRUE)

#define PKTQLEN (10)		/* Maximum length of the packet queue */

#define PKTSZ (IP_MAXPACKET + ETH_H)	/* Packet buffer size */
#define MINPKTSZ (size_t)(sizeof (struct ether_header) + sizeof (struct ip) + sizeof (struct tcphdr))
#define IPHLTOBYTES(HL) (HL << 2)
#define TCPOFFTOBYTES(OFF) (OFF << 2)
#define IPV4 (4)
#define PCAPFILTERTCP "(tcp)"
#define PCAPFILTERIP "(ip)"

/* global variables */

static struct globalVars_t
{
  char *dev;			/* device to read from */
  int optimizeFilter;		/* should we optimize the filter string? */
  char *outputFile;		/* file to transmit */
  FILE *ofp;			/* input file handle */
  eth_t *xmitContext;		/* transmission handle */
  char pseudoKey[PSEUDOKEYLENBYTES + 1];	/* secret 32-bit pseudo-key plus a NULL */
  rand_t *randHandle;		/* random number handle */
  uint32_t seq;			/* sequence number */
  u_char nextByte;		/* next byte to send */
} gv;

#endif /* __CDST_H */

/*
 * Covert Channel client/server
 *
 * $Id: pktRecv.h,v 1.1 2006/04/06 19:15:04 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#ifndef __PCAP_IF_H
#define __PCAP_IF_H

#include <pcap.h>

#define PCAP_SNAPLEN (BUFSIZ)
#define PCAP_PROMISC_ON (1)
#define PCAP_READTIMEOUT (1000)	/* in MS */
#define PCAP_COUNTINFINITE (-1)

void printDeviceList ();
pcap_t *initPktRecv (char *dev, char *rawFilter, int optimizeFilter);

#endif /* __PCAP-IF_H */

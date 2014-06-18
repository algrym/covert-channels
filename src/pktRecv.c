/*
 * Covert Channel client/server
 *
 * $Id: pktRecv.c,v 1.1 2006/04/06 19:15:04 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

/* Portions of this file were from winpcap.org's examples, requiring
   the following note. */

/*
 * Copyright (c) 1999 - 2003
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright 
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright 
 * notice, this list of conditions and the following disclaimer in the 
 * documentation and/or other materials provided with the distribution. 
 * 3. Neither the name of the Politecnico di Torino nor the names of its 
 * contributors may be used to endorse or promote products derived from 
 * this software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include <stdio.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "pktRecv.h"
#include "util.h"

static char pcapErrBuf[PCAP_ERRBUF_SIZE];	/* PCAP error buffer */

/* print the list of all devices */
void
printDeviceList ()
{
  pcap_if_t *devList, *dev;
  pcap_addr_t *addr;
  int i = 0;

  /* retrieve the device list */
  if (pcap_findalldevs (&devList, pcapErrBuf) != 0)
    {
      fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
      fprintf (stderr, "Couldn't get device list: %s\n", pcapErrBuf);
      exit (EX_UNAVAILABLE);
    }

  /* iterate through the list */
  for (dev = devList; dev != NULL; dev = dev->next)
    {
      printf ("%d. %s ", ++i, dev->name);

      /* print description, if available */
      if (dev->description)
	printf ("(%s)\n", dev->description);
      else
	printf ("(no description)\n");

      /* iterate through address list */
      for (addr = dev->addresses; addr != NULL; addr = addr->next)
	if (addr->addr->sa_family == AF_INET)
	  {
	    printf ("    IPv4:%s ",
		    inet_ntoa (((struct sockaddr_in *) addr->addr)->
			       sin_addr));
	    if (addr->netmask)
	      printf ("NMASK:%s ",
		      inet_ntoa (((struct sockaddr_in *) addr->netmask)->
				 sin_addr));
	    if (addr->broadaddr)
	      printf ("BCAST:%s ",
		      inet_ntoa (((struct sockaddr_in *) addr->broadaddr)->
				 sin_addr));
	    if (addr->dstaddr)
	      printf ("DST:%s ",
		      inet_ntoa (((struct sockaddr_in *) addr->dstaddr)->
				 sin_addr));
	    printf ("\n");
	  }
	else if (addr->addr->sa_family == AF_INET6)
	  printf ("    IPv6:?\n");
    }

  if (i == 0)
    {
      fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
      fprintf (stderr, "No interfaces found.");
      exit (EX_UNAVAILABLE);
    }

  /* free the device list */
  pcap_freealldevs (devList);
}

/* initialize PCAP handle */
pcap_t *
initPktRecv (char *dev, char *rawFilter, int optimizeFilter)
{
  pcap_t *captureHandle;
  struct bpf_program compiledFilter;	/* PCAP compiled filter expression */

  bpf_u_int32 ip, mask;		/* device information */

  /* lookup default device */
  if (dev == (char *) NULL)	/* have we already set a device name? */
    {
      dev = pcap_lookupdev (pcapErrBuf);
      if (dev == (char *) NULL)
	{
	  fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
	  fprintf (stderr, "Couldn't find default device: %s\n", pcapErrBuf);
	  exit (EX_UNAVAILABLE);
	}
    }

  /* get device information */
  if (pcap_lookupnet (dev, &ip, &mask, pcapErrBuf) < 0)
    {
      printf ("Using null device information for %s: %s\n", dev, pcapErrBuf);
      mask = ip = 0;
    }

  /* ip2str uses a static buffer, so printf calls must be seperated */
  printf ("Using device %s network %s netmask", dev, ip2str (ip));
  printf (" %s\n", ip2str (mask));

  /* open dev for sniffing */
  captureHandle = pcap_open_live (dev, PCAP_SNAPLEN, PCAP_PROMISC_ON,
				  PCAP_READTIMEOUT, pcapErrBuf);
  if (captureHandle == (pcap_t *) NULL)
    {
      fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
      fprintf (stderr, "Couldn't open device %s: %s\n", dev, pcapErrBuf);
      exit (EX_UNAVAILABLE);
    }

  /* don't worry about an empty filter */
  if ((rawFilter != (char *) NULL) && (strlen (rawFilter) > 0))
    {
      /* compile filter */
      if (pcap_compile (captureHandle, &compiledFilter, rawFilter,
			optimizeFilter, 0) < 0)
	{
	  fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
	  fprintf (stderr, "Couldn't parse filter \"%s\": %s\n", rawFilter,
		   pcap_geterr (captureHandle));
	  exit (EX_USAGE);
	}

      /* install filter */
      if (pcap_setfilter (captureHandle, &compiledFilter) < 0)
	{
	  fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
	  fprintf (stderr, "Couldn't install filter \"%s\": %s\n", rawFilter,
		   pcap_geterr (captureHandle));
	  exit (EX_USAGE);
	}
    }
  return captureHandle;
}

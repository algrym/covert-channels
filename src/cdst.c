/*
 * Covert Channel client/server
 *
 * $Id: cdst.c,v 1.5 2006/08/04 19:57:33 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include "cdst.h"

void
usage ()
{
  fprintf (stderr, "Usage:\n"
	   "  cdst -i interface [-O] [-D] -w filename PseudoKey\n\n"
	   "    -O, --do-not-optimize      Eschew the packet-matching code optimizer.\n"
	   "    -D, --find-all-devices     Display all available network devices.\n"
	   "    -i, --interface=IF         Listen on specified interface.\n"
	   "    -w, --write-file=FILENAME   Read data from specified file.\n\n"
	   "    Where \"PseudoKey\" is at least four random chars unique to source and dest.\n\n");

  exit (EX_USAGE);
}

/* handle command-line arguments */
void
processArgs (int argc, char **argv)
{
  int bflag, ch;

  /* argument/options descriptor */
  static struct option longopts[] = {
    {"interface", required_argument, NULL, 'i'},
    {"do-not-optimize", no_argument, NULL, 'O'},
    {"find-all-devices", no_argument, NULL, 'D'},
    {"write-file", required_argument, NULL, 'w'},
    {NULL, 0, NULL, 0}
  };

  /* print banner */
  printf ("cdst $Revision: 1.5 $ - A. J. Wright <ajw@utk.edu>\n"
	  "Information Security Office - University of Tennessee, Knoxville\n\n");

  /* set default values for optional arguments */
  gv.optimizeFilter = 1;

  bflag = 0;
  while ((ch = getopt_long (argc, argv, "DOi:w:", longopts, NULL)) != -1)
    switch (ch)
      {
      case 0:
	printf ("optarg: %s", optarg);
	break;
      case 'O':
	gv.optimizeFilter = 0;
	printf ("Filter optimization disabled.\n");
	break;
      case 'i':
	/* TODO: check return from strdup */
	gv.dev = strdup (optarg);
	break;
      case 'w':
	/* TODO: check return from strdup */
	gv.outputFile = strdup (optarg);
	if ((gv.ofp = fopen (gv.outputFile, "w")) == (FILE *) NULL)
	  {
	    fprintf (stderr, "%s(%d) fopen ", __FILE__, __LINE__);
	    perror (gv.outputFile);
	    exit (EX_USAGE);
	  }
	break;
      case 'D':
	/* print available devices */
	printDeviceList ();
	exit (EX_OK);
	break;
      default:
	usage ();
      }
  argc -= optind;
  argv += optind;

  /* set the global pseudo key */
  if (argc != 1)
    {
      fprintf (stderr, "%s(%d): pseudo key required.\n", __FILE__, __LINE__);
      usage ();
    }
  strncpy (gv.pseudoKey, argv[0], PSEUDOKEYLENBYTES - 1);

  /* ensure we have an input file */
  if (gv.ofp == (FILE *) NULL)
    {
      fprintf (stderr, "%s(%d): input file required.\n", __FILE__, __LINE__);
      usage ();
    }

  /* ensure we have an ethernet device */
  if (gv.dev == (char *) NULL)
    {
      fprintf (stderr, "%s(%d): network device required.\n", __FILE__,
	       __LINE__);
      usage ();
    }
}

/* callback specifies a routine to be called with three arguments: a
   u_char pointer which is passed in from pcap_dispatch(), a pointer to
   the pcap_pkthdr struct (which precede the actual network headers and
   data), and a u_char pointer to the packet data.
*/
void
pktHandler (u_char * user, const struct pcap_pkthdr *h, const u_char * bytes)
{
  /*  u_int8_t etherSrc, etherDst;
     u_int16_t etherType; */
  struct ether_header *etherPkt;
  struct ip *ipPkt;
  struct tcphdr *tcpPkt;
  u_char c;

  printf ("\n");

  /* ensure that we're not going to run off the end of the packet */
  if (h->caplen < MINPKTSZ)
    {
      printf ("Skipping packet: capture length (%u) < MINPKTSZ (%lu)\n",
	      h->caplen, MINPKTSZ);
      return;
    }

  /* TODO: make sure we're not looking at a packet we sent */
  /* TODO: make sure this packet's destination is one we want */

  /*
   * decode this packet
   */

  /* get ethernet packet info */
  etherPkt = (struct ether_header *) bytes;
  printf ("Ether: %02hx:%02hx:%02hx:%02hx:%02hx:%02hx -> "
	  "%02hx:%02hx:%02hx:%02hx:%02hx:%02hx (%04hx)\n",
	  etherPkt->ether_shost[0], etherPkt->ether_shost[1],
	  etherPkt->ether_shost[2], etherPkt->ether_shost[3],
	  etherPkt->ether_shost[4], etherPkt->ether_shost[5],
	  etherPkt->ether_dhost[0], etherPkt->ether_dhost[1],
	  etherPkt->ether_dhost[2], etherPkt->ether_dhost[3],
	  etherPkt->ether_dhost[4], etherPkt->ether_dhost[5],
	  etherPkt->ether_type);

  /* ensure we're dealing with IPv4 */
  if (ntohs (etherPkt->ether_type) != ETHERTYPE_IP)
    {
      printf ("Skipping packet: ether type (%04hx) != ETHERTYPE_IP (%04hx)\n",
	      ntohs (etherPkt->ether_type), ETHERTYPE_IP);
      return;
    }

  ipPkt = (struct ip *) (bytes + sizeof (struct ether_header));
  if (ipPkt->ip_v != IPV4)
    {
      printf ("Skipping packet: IP version (%04hi) != IPv4 (%04hi)\n",
	      ipPkt->ip_v, IPV4);
      return;
    }

  /* get IP packet info */
  /* inet_ntoa uses a static buffer, so printf calls must be seperated */
  printf ("IPv4: %s", inet_ntoa (ipPkt->ip_src));
  printf
    (" (%x) -> %s (%x) (%04hx)\n       hl:%04hx id:%04hx off:%04x ttl:%hu",
     ipPkt->ip_src.s_addr, inet_ntoa (ipPkt->ip_dst), ipPkt->ip_dst.s_addr,
     ipPkt->ip_p, IPHLTOBYTES (ipPkt->ip_hl), ipPkt->ip_id, ipPkt->ip_off,
     ipPkt->ip_ttl);

  if (ipPkt->ip_off & IP_RF)
    printf (" RF");
  if (ipPkt->ip_off & IP_DF)
    printf (" DF");
  if (ipPkt->ip_off & IP_MF)
    printf (" MF");

  printf ("\n");

#if(ENCODING==2)
  if (ipPkt->ip_p != IPPROTO_TCP)
    {
      printf ("Skipping packet: IP protocol (%04hi) != TCP (%04hi)\n",
	      ipPkt->ip_p, IPPROTO_TCP);
      return;
    }

  /* get TCP packet info */
  tcpPkt =
    (struct tcphdr *) (bytes + sizeof (struct ether_header) +
		       IPHLTOBYTES (ipPkt->ip_hl));
  printf ("TCP: %u -> %u seq:%x ack:%x flags:%x off:%u", tcpPkt->th_sport,
	  tcpPkt->th_dport, tcpPkt->th_seq, tcpPkt->th_ack, tcpPkt->th_flags,
	  TCPOFFTOBYTES (tcpPkt->th_off));

  /* discover flag settings */
  if (tcpPkt->th_flags & TH_FIN)
    printf (" FIN");
  if (tcpPkt->th_flags & TH_SYN)
    printf (" SYN");
  if (tcpPkt->th_flags & TH_RST)
    printf (" RST");
  if (tcpPkt->th_flags & TH_PUSH)
    printf (" PUSH");
  if (tcpPkt->th_flags & TH_ACK)
    printf (" ACK");
  if (tcpPkt->th_flags & TH_URG)
    printf (" URG");
  if (tcpPkt->th_flags & TH_ECE)
    printf (" ECE");
  if (tcpPkt->th_flags & TH_CWR)
    printf (" CWR");
  printf ("\n");
#endif /* ENCODING==2 */

  /*
   * check the packet for information
   */

#if(ENCODING==2)
  if (isTwoEncoded (ipPkt, tcpPkt, gv.pseudoKey))
    {
      c = decodeTwo (ipPkt, tcpPkt, gv.pseudoKey);
      printf ("Packet encoded byte (%x)\n", c);
      if (isprint (c))
	fprintf (stderr, "%c", c);

      if (fwrite (&c, sizeof (c), 1, gv.ofp) < 1)
	{
	  fprintf (stderr, "%s(%d) ", __FILE__, __LINE__);
	  perror (gv.outputFile);
	  exit (EX_OSERR);
	}
      fflush (gv.ofp);
    }
#else /* ENCODING==1 */
  /* ensure the packet isn't already encoded */
  if (isOneEncoded (ipPkt, gv.pseudoKey[0]))
    {
      c = decodeOne (ipPkt);
      printf ("Packet encoded byte (%x)\n", c);
      if (isprint (c))
	fprintf (stderr, "%c", c);

      if (fwrite (&c, sizeof (c), 1, gv.ofp) < 1)
	{
	  fprintf (stderr, "%s(%d) ", __FILE__, __LINE__);
	  perror (gv.outputFile);
	  exit (EX_OSERR);
	}
      fflush (gv.ofp);
    }
#endif

  dumpRam (bytes, h->caplen);
}

int
main (int argc, char *argv[])
{
  pcap_t *captureHandle;

  /* initialize global struct */
  memset (&gv, 0, sizeof (gv));

  /* initialize random number handler */
  if ((gv.randHandle = rand_open ()) == NULL)
    {
      fprintf (stderr, "%s(%d) ", __FILE__, __LINE__);
      perror ("rand_open");
      exit (EX_OSERR);
    }

  /* process argument list */
  processArgs (argc, argv);

  /* initialize input handle */
  captureHandle = initPktRecv (gv.dev, PCAPFILTERIP, TRUE);
  /* captureHandle = initPktRecv (gv.dev, PCAPFILTERTCP, TRUE);  */
  /* captureHandle = initPktRecv (gv.dev, NULL, TRUE); */

  /* initialize output context */
  gv.xmitContext = initPktXmit (gv.dev);

  /* loop through packets as they come in */
  if (pcap_loop (captureHandle, PCAP_COUNTINFINITE, pktHandler, NULL) == -1)
    {
      fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
      fprintf (stderr, "pcap_loop error: %s\n", pcap_geterr (captureHandle));
      exit (EX_USAGE);
    }

  return EX_OK;
}

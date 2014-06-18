/*
 * Covert Channel client/server
 *
 * $Id: csrc.c,v 1.17 2006/08/04 19:57:34 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#include <string.h>
#include <getopt.h>

#include "csrc.h"

void
usage ()
{
  fprintf (stderr, "Usage:\n"
	   "  csrc -i interface [-O] [-D] -r filename PseudoKey\n\n"
	   "    -O, --do-not-optimize      Eschew the packet-matching code optimizer.\n"
	   "    -D, --find-all-devices     Display all available network devices.\n"
	   "    -i, --interface=IF         Listen on specified interface.\n"
	   "    -r, --read-file=FILENAME   Read data from specified file.\n\n"
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
    {"read-file", required_argument, NULL, 'r'},
    {NULL, 0, NULL, 0}
  };

  /* print banner */
  printf
    ("csrc $Revision: 1.17 $ (encoding method %i)- A. J. Wright <ajw@utk.edu>\n"
     "Information Security Office - University of Tennessee, Knoxville\n\n",
     ENCODING);

  /* set default values for optional arguments */
  gv.optimizeFilter = 1;

  bflag = 0;
  while ((ch = getopt_long (argc, argv, "DOi:r:", longopts, NULL)) != -1)
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
	gv.dev = strdup (optarg);
	if (gv.dev == (char *) NULL)
	  {
	    fprintf (stderr, "%s(%d) ", __FILE__, __LINE__);
	    perror ("strdup");
	    exit (EX_OSERR);
	  }
	break;
      case 'r':
	gv.inputFile = strdup (optarg);
	if (gv.inputFile == (char *) NULL)
	  {
	    fprintf (stderr, "%s(%d) ", __FILE__, __LINE__);
	    perror ("strdup");
	    exit (EX_OSERR);
	  }
	if ((gv.ifp = fopen (gv.inputFile, "r")) == (FILE *) NULL)
	  {
	    fprintf (stderr, "%s(%d) fopen ", __FILE__, __LINE__);
	    perror (gv.inputFile);
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
  if (gv.ifp == (FILE *) NULL)
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

u_char
getNextByte ()
{
  u_char c;
  if (fread (&c, sizeof (u_char), 1, gv.ifp) <= 0)
    {
      if (feof (gv.ifp))
	return 0;
      fprintf (stderr, "%s(%d) ", __FILE__, __LINE__);
      perror ("fread");
      exit (EX_IOERR);
    }
  return c;
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
  size_t bytesOut = 0;

  printf ("\n");

  /* ensure that we're not going to run off the end of the packet */
  if (h->caplen < MINPKTSZ)
    {
      printf ("Skipping packet: capture length (%u) < MINPKTSZ (%lu)\n",
	      h->caplen, MINPKTSZ);
      return;
    }

  /* TODOy: make sure this packet's destination is one we want or change destination address */

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
   * Setup the new packet for transmit
   */

#if(ENCODING==2)
  /* ensure the packet isn't already encoded */
  if (isTwoEncoded (ipPkt, tcpPkt, gv.pseudoKey))
    {
      printf ("Skipping packet: already encoded (%x)\n", decodeOne (ipPkt));
      return;
    }

  /* modify the packet, and return if it's not usuable */
  if (!encodeTwo
      (ipPkt, tcpPkt, gv.nextByte, gv.pseudoKey, rand_uint32 (gv.randHandle)))
    return;

#else /* ENCODING=1 */
  /* ensure the packet isn't already encoded */
  if (isOneEncoded (ipPkt, gv.pseudoKey[0]))
    {
      printf ("Skipping packet: already encoded (%x)\n", decodeOne (ipPkt));
      return;
    }

  /* modify the packet, and return if it's not usuable */
  if (!encodeOne
      (ipPkt, gv.nextByte, gv.pseudoKey[0], rand_uint8 (gv.randHandle)))
    return;

#endif


  printf ("Encoded byte of (%x)\n", decodeOne (ipPkt));

  /* calculate the checksums for the headers */
  tcp_cksum (ipPkt, tcpPkt,
	     (h->caplen - (sizeof (struct ip) + sizeof (struct tcphdr))));
  ip_cksum (ipPkt);

  /* transmit the new packet */
  bytesOut = eth_send (gv.xmitContext, bytes, h->caplen);
  printf ("XMIT: sent %lu bytes from a %lu byte receipt. (%x)\n", bytesOut,
	  (size_t) h->caplen, gv.nextByte);

  /* get the next byte to print */
  gv.nextByte = getNextByte ();

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

  /* initialize first byte */
  gv.nextByte = getNextByte ();

  /* loop through packets as they come in */
  if (pcap_loop (captureHandle, PCAP_COUNTINFINITE, pktHandler, NULL) == -1)
    {
      fprintf (stderr, "%s(%d): ", __FILE__, __LINE__);
      fprintf (stderr, "pcap_loop error: %s\n", pcap_geterr (captureHandle));
      exit (EX_USAGE);
    }

  return EX_OK;
}

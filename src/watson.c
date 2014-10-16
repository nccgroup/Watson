/*
A lightweight packet capture application with

* support for hardware timestamping (ns accuracy)
* no external lib requirements (no libpcap)
* TPACKET_V3 RX_RING using AF_PACKET

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed for John Green, cirt at nccgroup dot com

https://github.com/nccgroup/watson

Released under AGPL see LICENSE for more information
*/


/* Originally based on example code provided within 
 * https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
 */
#define _GNU_SOURCE

#include "watson.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sched.h>

/* Global */
static unsigned long packets_total = 0, bytes_total = 0;
static sig_atomic_t sigint = 0;
static pcapOption_t pcapOption;

static void
printHelp ()
{

  fprintf (stderr, "\
Usage: watson [OPTION]...\n\
Captures network traffic and writes to disk\n\
\n\
-d, --directory specific directory to create files [MANDATORY]\n\
-i, --interface capture interface [MANDATORY]\n\
-h, --help	prints this help\n\
-v, --verbose	verbose\n\
-s, --filesize 	filesize (default 0 - grow indefinitely)\n\
-r, --ringsize  ringsize (default 256M and be multiple of blocksize)\n\
-c, --cpu	bind to cpu\n\
-f, --format    output format (1=pcap, 2=pcapns,...)\n\
-l, --linktype  linktype (1=LINKTYPE_ETHERNET (with layer2), 101=LINKTYPE_RAW( w/o layer2)\n\
");
  exit (0);

}

static long
bytes_from_multiplier (char *inString)
{
/* Returns the number of bytes in a number with suffix */
/* Supports K, M, G */
/* We work in powers of 2  (eg 1024 bytes in 1K) */

  long value = 0;
  long factor = 1;
  char *suffix;

  value = strtol (inString, &suffix, 10);

  if (suffix)
    {
      /* We have a suffix */

      switch (*suffix)
	{
	case 'G':
	  factor = 1 << 30;
	  break;
	case 'M':
	  factor = 1 << 20;
	  break;
	case 'K':
	  factor = 1 << 10;
	  break;
	default:
	  /* Unknown suffix, ignore */
	  break;
	}

    }

  return (value * factor);

}


static void
get_options (int argc, char *argv[])
{
  int c;

  memset (&pcapOption, 0, sizeof (pcapOption_t));

/* Set defaults where != 0 */
  pcapOption.cpu = -1;
  pcapOption.format = FORMAT_PCAP_US;
  pcapOption.linktype = LINKTYPE_ETHERNET;
  pcapOption.ringsize = 1 << 28;

  while (1)
    {
      static struct option long_options[] = {
	{"verbose", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{"directory", required_argument, 0, 'd'},
	{"interface", required_argument, 0, 'i'},
	{"filesize", required_argument, 0, 's'},
	{"ringsize", required_argument, 0, 'r'},
	{"cpu", required_argument, 0, 'c'},
	{"format", required_argument, 0, 'f'},
	{"linktype", required_argument, 0, 'l'},
	{0, 0, 0, 0}
      };
      int option_index = 0;
      c =
	getopt_long (argc, argv, "vhd:i:s:r:c:p:f:l:", long_options,
		     &option_index);

      if (c == -1)
	break;

      switch (c)
	{
	case 0:
	  break;
	case 'v':
	  pcapOption.verbose = 1;
	  break;
	case 'd':
	  strncpy (pcapOption.directory, optarg, OPTION_SIZE - 1);
	  break;
	case 'i':
	  strncpy (pcapOption.interface, optarg, OPTION_SIZE - 1);
	  break;
	case 's':
	  pcapOption.filesize = bytes_from_multiplier (optarg);
	  break;
	case 'r':
	  pcapOption.ringsize = bytes_from_multiplier (optarg);
	  break;
	case 'c':
	  pcapOption.cpu = atoi (optarg);
	  break;
	case 'f':
	  pcapOption.format = atoi (optarg);
	  break;
	case 'l':
	  pcapOption.linktype = atoi (optarg);
	  break;
	case 'h':
	case '?':
	default:
	  printHelp ();
	  break;
	}
    }

  if (!pcapOption.interface[0] || !pcapOption.directory[0])
    printHelp ();

  switch (pcapOption.format)
    {
    case (FORMAT_PCAP_NS):
    case (FORMAT_PCAP_US):
      break;
    default:
      printHelp ();
      break;
    }

  switch (pcapOption.linktype)
    {
    case (LINKTYPE_ETHERNET):
    case (LINKTYPE_RAW):
      break;
    default:
      printHelp ();
      break;
    }


}

static void
sighandler (int num)
{
  sigint = 1;
}

static int
setup_socket (ring_t * ring, char *netdev)
{
  int err, i, fd, v = TPACKET_V3;
  struct sockaddr_ll ll;
  unsigned int blocksiz = 1 << 22, framesiz = 1 << 11;
  unsigned int blocknum = 64;
  struct hwtstamp_config hwconfig;
  struct ifreq ifr;
  int ret;
  int timesource = 0;

  blocknum = pcapOption.ringsize / blocksiz;

  if (pcapOption.verbose)
    {
      printf ("RING CONFIG\n");
      printf ("Frame size %u\n", framesiz);
      printf ("Block size %u\n", blocksiz);
      printf ("Block number %u\n", blocknum);
      printf ("Buffer size %u\n", blocknum * blocksiz);
    }

  /* Changing ETH_P_ALL to ETH_P_IP doesn't seem to make any difference */
  fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

  if (fd < 0)
    {
      perror ("socket SOCK_RAW");
      exit (1);
    }

/* Request HW timestamping */
  memset (&hwconfig, 0, sizeof (hwconfig));
  hwconfig.tx_type = HWTSTAMP_TX_OFF;
  hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

  timesource |= SOF_TIMESTAMPING_RAW_HARDWARE;
  timesource |= SOF_TIMESTAMPING_SYS_HARDWARE;

  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, netdev, sizeof (ifr.ifr_name));
  ifr.ifr_data = (void *) &hwconfig;
  ret = ioctl (fd, SIOCSHWTSTAMP, &ifr);
  if (ret < 0)
    {
      perror ("ioctl SIOCSHWTSTAMP");
      /* HW timestamps aren't support so will fall back to software */
    }

  err = setsockopt (fd, SOL_PACKET, PACKET_VERSION, &v, sizeof (v));
  if (err < 0)
    {
      perror ("setsockopt PACKET_VERSION");
      exit (1);
    }

  err =
    setsockopt (fd, SOL_PACKET, PACKET_TIMESTAMP, &timesource,
		sizeof (timesource));
  if (err < 0)
    {
      perror ("setsockopt PACKET_TIMESTAMP");
      exit (1);
    }

  memset (&ring->req, 0, sizeof (ring->req));
  ring->req.tp_block_size = blocksiz;
  ring->req.tp_frame_size = framesiz;
  ring->req.tp_block_nr = blocknum;
  ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
  ring->req.tp_retire_blk_tov = 60;
  ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

  err = setsockopt (fd, SOL_PACKET, PACKET_RX_RING, &ring->req,
		    sizeof (ring->req));
  if (err < 0)
    {
      perror ("setsockopt PACKET_RX_RING");
      exit (1);
    }

  ring->map = mmap (NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
  if (ring->map == MAP_FAILED)
    {
      perror ("mmap");
      exit (1);
    }

  ring->rd = malloc (ring->req.tp_block_nr * sizeof (*ring->rd));
  assert (ring->rd);
  for (i = 0; i < ring->req.tp_block_nr; ++i)
    {
      ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
      ring->rd[i].iov_len = ring->req.tp_block_size;
    }

  memset (&ll, 0, sizeof (ll));
  ll.sll_family = PF_PACKET;

  switch (pcapOption.linktype)
    {
    case (LINKTYPE_ETHERNET):
      ll.sll_protocol = htons (ETH_P_ALL);
      break;
    case (LINKTYPE_RAW):
      ll.sll_protocol = htons (ETH_P_IP);
      break;
    default:
      panic ("Unknown linktype");
      break;
    }



  //ll.sll_protocol = htons (ETH_P_ALL);
  ll.sll_ifindex = if_nametoindex (netdev);
  ll.sll_hatype = 0;
  ll.sll_pkttype = 0;
  ll.sll_halen = 0;

  err = bind (fd, (struct sockaddr *) &ll, sizeof (ll));
  if (err < 0)
    {
      perror ("bind");
      exit (1);
    }

  return fd;
}

static FILE *
get_pcap_stream (uint32_t tvsec)
{
  /* Retrieves the FILE for the current PCAP.  Open new one based on tvsec
     with header if required */
  static FILE *pcap = NULL;
  size_t written;
  char filename[OPTION_SIZE] = "";

  pcapfile_header_t pcap_header;

  if (tvsec == 0)
    {
      /* tvsec == 0 which means close outstanding file and return */
      if (pcap)
	{
	  fclose (pcap);
	  pcap = NULL;
	}
      return NULL;
    }

/* TODO: Perhaps not call ftell() each time */
  if (pcap && pcapOption.filesize && (ftell (pcap) > pcapOption.filesize))
    {
      /* Current file is larger than specified max.  close so a new one is opened */
      fclose (pcap);
      pcap = NULL;
    }


  if (!pcap)
    {
      /* No file currently open, so open a new one */
      snprintf (filename, sizeof (filename), "%s/%u.pcap",
		pcapOption.directory, tvsec);
      pcap = fopen (filename, "w");

      if (pcapOption.verbose)
	printf ("Writing to %s\n", filename);

      if (!pcap)
	{
	  perror ("get_pcap_stream1");
	  exit (1);
	}

      switch (pcapOption.format)
	{
	case (FORMAT_PCAP_US):
	  pcap_header.magic_number = PCAP_USEC_MAGIC;
	  break;
	case (FORMAT_PCAP_NS):
	  pcap_header.magic_number = PCAP_NSEC_MAGIC;
	  break;
	default:
	  panic ("Unknown output format\n");
	  break;
	}

      pcap_header.version_major = 2;
      pcap_header.version_minor = 4;
      pcap_header.thiszone = 0;
      pcap_header.sigfigs = 0;
      pcap_header.snaplen = 65535;
      pcap_header.network = pcapOption.linktype;	/*LINKTYPE_ETHERNET or LINKTYPE_RAW */

      written = fwrite (&pcap_header, sizeof (pcapfile_header_t), 1, pcap);
      if (written != 1)
	{
	  perror ("get_pcap_stream2");
	  exit (1);
	}

    }

  return pcap;


}

static void
display (struct tpacket3_hdr *ppd)
{
  struct pcapfile_pkt_hdr_t pkt_hdr;

  FILE *pcap;
  void *data;
  size_t ret;

  pkt_hdr.ts_sec = ppd->tp_sec;
  switch (pcapOption.format)
    {
    case (FORMAT_PCAP_US):
      pkt_hdr.ts_nsec = ppd->tp_nsec / 1000;
      break;
    case (FORMAT_PCAP_NS):
      pkt_hdr.ts_nsec = ppd->tp_nsec;
      break;
    default:
      panic ("Unknown format");
      break;
    }

  switch (pcapOption.linktype)
    {
    case (LINKTYPE_ETHERNET):

      pkt_hdr.caplen = ppd->tp_snaplen;
      pkt_hdr.wirelen = ppd->tp_len;
      data = (char *) ((uint8_t *) ppd + ppd->tp_mac);
      break;
    case (LINKTYPE_RAW):
      pkt_hdr.caplen = ppd->tp_snaplen - (ppd->tp_net - ppd->tp_mac);
      pkt_hdr.wirelen = ppd->tp_len - (ppd->tp_net - ppd->tp_mac);
      data = (char *) ((uint8_t *) ppd + ppd->tp_net);
      break;
    default:
      panic ("Unsupported linktype requested\n");
      break;

    }

  pcap = get_pcap_stream (pkt_hdr.ts_sec);

  ret = fwrite (&pkt_hdr, sizeof (pkt_hdr), 1, pcap);
  if (ret != 1)
    {
      perror ("display");
      exit (1);
    }

  ret = fwrite (data, pkt_hdr.caplen, 1, pcap);

  if (ret != 1)
    {
      perror ("display");
      exit (1);
    }

  if (pcapOption.verbose)
    {
      /* Check all 3 bits in the event of more than one being set */
      if ((ppd->tp_status & TP_STATUS_TS_SYS_HARDWARE) != 0)
	printf ("TS SYS HW\n");
      if ((ppd->tp_status & TP_STATUS_TS_RAW_HARDWARE) != 0)
	printf ("TS RAW HW\n");
      if ((ppd->tp_status & TP_STATUS_TS_SOFTWARE) != 0)
	printf ("TS SOFTWARE\n");
      if (ppd->tp_status < TP_STATUS_TS_SOFTWARE)
	printf ("TS FALLBACK\n");

    }
}

static void
walk_block (block_desc_t * pbd, const int block_num)
{
  int num_pkts = pbd->h1.num_pkts, i;
  unsigned long bytes = 0;
  struct tpacket3_hdr *ppd;


  ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
				 pbd->h1.offset_to_first_pkt);
  for (i = 0; i < num_pkts; ++i)
    {
      bytes += ppd->tp_snaplen;
      display (ppd);

      ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);
    }

  packets_total += num_pkts;
  bytes_total += bytes;
}

static void
flush_block (block_desc_t * pbd)
{
  pbd->h1.block_status = TP_STATUS_KERNEL;
}

static void
teardown_socket (ring_t * ring, int fd)
{
  munmap (ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
  free (ring->rd);
  close (fd);
}


static void
set_irq_affinity (void)
{
  char buff[128];
  char sysname[128];
  FILE *fp;
  int irq;

/* This currently does nothing */
  return;
/* /sys/class/net/p2p1/device/msi_irqa/ on HP Microserver */
  snprintf (sysname, sizeof (buff), "/sys/class/net/%s/device/irq",
	    pcapOption.interface);

  fp = fopen (sysname, "r");
  if (!fp)
    return;

  memset (buff, 0, sizeof (buff));
  if (fgets (buff, sizeof (buff) - 1, fp) != NULL)
    {
      irq = atoi (buff);
    }
  fclose (fp);

  printf ("irq %d\n", irq);

}

static void
panic (char *msg)
{

  fprintf (stderr, "Error: %s\n", msg);
  exit (1);

}


static void
cpu_affinity (int cpu)
{
  int ret;
  cpu_set_t cpu_bitmask;

  CPU_ZERO (&cpu_bitmask);
  CPU_SET (cpu, &cpu_bitmask);

  ret = sched_setaffinity (getpid (), sizeof (cpu_bitmask), &cpu_bitmask);
  if (ret)
    panic ("Can't set this cpu affinity!\n");

}


static int
set_proc_prio (int priority)
{
  int ret = setpriority (PRIO_PROCESS, getpid (), priority);
  if (ret)
    panic ("Can't set nice val\n");

  return 0;
}


int
main (int argc, char **argv)
{
  int fd, err;
  socklen_t len;
  ring_t ring;
  struct pollfd pfd;
  unsigned int block_num = 0, blocks = 64;
  block_desc_t *pbd;
  struct tpacket_stats_v3 stats;

  get_options (argc, argv);

  set_proc_prio (-20);

  if (pcapOption.cpu >= 0)
    {
      set_irq_affinity ();	//pcapOption.interface, pcapOption.cpu);
      cpu_affinity (pcapOption.cpu);
    }

  /* Register signal handler */
  signal (SIGINT, sighandler);

  memset (&ring, 0, sizeof (ring));
  fd = setup_socket (&ring, pcapOption.interface);
  assert (fd > 0);

  memset (&pfd, 0, sizeof (pfd));
  pfd.fd = fd;
  pfd.events = POLLIN;		// | POLLERR;
  pfd.revents = 0;

  while (likely (!sigint))
    {
      pbd = (block_desc_t *) ring.rd[block_num].iov_base;

      if ((pbd->h1.block_status & TP_STATUS_USER) == 0)
	{
	  /* Wait for a packet to arrive */
	  poll (&pfd, 1, -1);
	  continue;
	}

      walk_block (pbd, block_num);
      flush_block (pbd);
      block_num = (block_num + 1) % blocks;
    }

  len = sizeof (stats);
  err = getsockopt (fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
  if (err < 0)
    {
      perror ("getsockopt PACKET_STATISTICS");
      exit (1);
    }

  fflush (stdout);
  printf ("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n",
	  stats.tp_packets, bytes_total, stats.tp_drops,
	  stats.tp_freeze_q_cnt);

  /* Close pcap if open */
  get_pcap_stream (0);

  teardown_socket (&ring, fd);
  return 0;
}

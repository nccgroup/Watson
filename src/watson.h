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

#include <stdio.h>
#include <stdint.h>
#include <linux/if_packet.h>

#define OPTION_SIZE (1024)

/* Rx and Tx ring - header status */
#define TP_STATUS_TS_SOFTWARE           (1 << 29)
#define TP_STATUS_TS_SYS_HARDWARE       (1 << 30)
#define TP_STATUS_TS_RAW_HARDWARE       (1 << 31)

#ifndef likely
#define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

/* From pcap-linktype so we don't have to include pcap.h */
#define LINKTYPE_ETHERNET (1)
#define LINKTYPE_RAW (101)
#define PCAP_USEC_MAGIC (0xa1b2c3d4)
#define PCAP_NSEC_MAGIC (0xa1b23c4d)

/* Structs */
typedef enum {FORMAT_PCAP_US=1, FORMAT_PCAP_NS} format_t;

typedef struct block_desc_t
{
  uint32_t version;
  uint32_t offset_to_priv;
  struct tpacket_hdr_v1 h1;
} block_desc_t;

typedef struct ring_t
{
  struct iovec *rd;
  uint8_t *map;
  struct tpacket_req3 req;
} ring_t;

typedef struct pcapfile_header_t
{
  uint32_t magic_number;	/* magic number */
  uint16_t version_major;	/* major version number */
  uint16_t version_minor;	/* minor version number */
  int32_t thiszone;		/* GMT to local correction */
  uint32_t sigfigs;		/* timestamp accuracy */
  uint32_t snaplen;		/* aka "wirelen" */
  uint32_t network;		/* data link type */
} pcapfile_header_t;

typedef struct pcapfile_pkt_hdr_t
{
  uint32_t ts_sec;		/* Seconds portion of the timestamp */
  uint32_t ts_nsec;		/* Nanoseconds portion of the timestamp */
  uint32_t caplen;		/* Capture length of the packet */
  uint32_t wirelen;		/* The wire length of the packet */
} pcapfile_pkt_hdr_t;

typedef struct pcapOption_t
{
  char directory[OPTION_SIZE];
  long filesize;
  long ringsize;
  char interface[OPTION_SIZE];
  int verbose;
  int cpu;
  format_t format;
  int linktype;
} pcapOption_t;

/* watson.c */
static void printHelp(void);
static long bytes_from_multiplier(char *inString);
static void get_options(int argc, char *argv[]);
static void sighandler(int num);
static int setup_socket(ring_t *ring, char *netdev);
static FILE *get_pcap_stream(uint32_t tvsec);
static void display(struct tpacket3_hdr *ppd);
static void walk_block(block_desc_t *pbd, const int block_num);
static void flush_block(block_desc_t *pbd);
static void teardown_socket(ring_t *ring, int fd);
static void set_irq_affinity(void);
static void panic(char *msg);
static void cpu_affinity(int cpu);
static int set_proc_prio(int priority);
int main(int argc, char **argv);

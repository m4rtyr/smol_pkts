/**
 * @Author: S. Sharma <m4rtyr>
 * @Date:   2020-01-24T20:25:03-06:00
 * @Email:  silentcat@protonmail.com
 * @Last modified by:   m4rtyr
 * @Last modified time: 2020-01-25T23:35:47-06:00
 */

#ifndef PKT_H
#define PKT_H

#include "dbg.h"

#include <stdlib.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <ifaddrs.h>
#include <net/if.h>

#define BPF_DEVICES_COUNT 99
#define BPF_DEVICE_NAME_LEN 10

#define FAILURE 0
#define SUCCESS 1

#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN  15

/* Taken from net/ethernet.h */

#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHERTYPE_ARP           0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP        0x8035  /* reverse Addr. resolution protocol */
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPV6          0x86dd  /* IPv6 */
#define ETHERTYPE_PAE           0x888e  /* EAPOL PAE/802.1x */
#define ETHERTYPE_RSN_PREAUTH   0x88c7  /* 802.11i / RSN Pre-Authentication */
#define ETHERTYPE_PTP           0x88f7  /* IEEE 1588 Precision Time Protocol */
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */

int sock;
char *buff;

/* NOTE: Some fields are combined together to prevent issues
 with bit endianness. */

typedef struct ether_header
{
  uint8_t ether_dhost[ETH_ADDR_LEN];
  uint8_t ether_shost[ETH_ADDR_LEN];
  uint16_t ether_type;
} ETH;

typedef struct ip
{
  uint8_t version_ihl;
  uint8_t dscp_ecn;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off_flags;
  uint8_t ttl;
  uint8_t proto;
  uint16_t chksum;
  uint32_t src;
  uint32_t dst;
} IP;

typedef struct tcp
{
  uint16_t src;
  uint16_t dst;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_off : 4;
  uint8_t reserved : 6;
  uint8_t ctrl_bits : 6;
  uint16_t window;
  uint16_t chksum;
  uint16_t urg_ptr;
} TCP;

typedef struct udp
{
  uint16_t src;
  uint16_t dst;
  uint16_t length;
  uint16_t chksum;
} UDP;

int open_dev(void);
const char *get_device_name(void);
int assoc_dev(int bpf, const char *device_name);
int set_pkt_insn(int bpf);
int set_up_socket(void);
void event_loop(void);
void process_pkt(int bytes_read, char *data);

/* Processing packet layers */
void process_ether(char *data);
void process_ip(char *data);

void process_layers(uint8_t proto, char *data);

void process_tcp(char *data);
void process_udp(char *data);

#endif

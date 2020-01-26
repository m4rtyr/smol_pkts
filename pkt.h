/**
 * @Author: S. Sharma <m4rtyr>
 * @Date:   2020-01-24T20:25:03-06:00
 * @Email:  silentcat@protonmail.com
 * @Last modified by:   m4rtyr
 * @Last modified time: 2020-01-25T22:37:47-06:00
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
#include <net/ethernet.h>

#define BPF_DEVICES_COUNT 99
#define BPF_DEVICE_NAME_LEN 10
#define FAILURE 0
#define SUCCESS 1

#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN 15

/* NOTE: Some fields are combined together to prevent issues
 with bit endianness. */

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
void event_loop(void);
void process_pkt(int bytes_read, char *data);

/* Processing packet layers */
void process_ether(char *data);
void process_ip(char *data);

void process_layers(uint8_t proto, char *data);

void process_tcp(char *data);
void process_udp(char *data);

#endif

/**
 * @Author: S. Sharma <m4rtyr>
 * @Date:   2020-01-24T20:25:01-06:00
 * @Email:  silentcat@protonmail.com
 * @Last modified by:   m4rtyr
 * @Last modified time: 2020-02-02T22:22:21-06:00
 */

#include "pkt.h"

time_t start = 0;

pcap_t *open_dev(const char *dev)
{
  char errbuff[PCAP_ERRBUF_SIZE+1];
  pcap_t *descr = pcap_open_live(dev, BUFSIZ, 1, TIMEOUT, errbuff);
  check_mem(descr);
  return descr;
error:
  log_err("%s", errbuff);
  return NULL;
}

const char *get_device_name()
{
  char errbuff[PCAP_ERRBUF_SIZE+1];
  const char *dev = pcap_lookupdev(errbuff);
  check_mem(dev);
  return dev;
error:
  log_err("%s", errbuff);
  return NULL;
}

void event_loop(const char *device_name)
{
  int cnt = 0;
  char errbuff[PCAP_ERRBUF_SIZE+1];
  s = (device_name == NULL) ? open_dev(get_device_name()) : open_dev(device_name);
  check_no_out(s != NULL);
  time(&start);
  pcap_setnonblock(s, 1, errbuff);

  do {
    if (s)
      cnt = pcap_dispatch(s, 0, process_pkt, NULL);
    else
      break;
  } while (cnt >= 0);
  return;
error:
  log_err("%s", errbuff);
  return;
}

void process_pkt(u_char *user,
                const struct pcap_pkthdr *h, const u_char *bytes)
{
  printf("[%Lf] ", h->ts.tv_sec + h->ts.tv_usec / MILLION - (double)start);
  process_ether(bytes);
}

void process_ether(const u_char *data)
{
  ETH *eth = (ETH *) data;
  for (int i = 0; i < ETH_ADDR_LEN; i++) {
    printf("%02X%s", eth->ether_shost[i],
        (i == ETH_ADDR_LEN-1 ? "" : ":"));
  }
  printf(" -> ");
  for (int i = 0; i < ETH_ADDR_LEN; i++) {
    printf("%02X%s", eth->ether_dhost[i],
        (i == ETH_ADDR_LEN-1 ? "" : ":"));
  }
  printf(", ");
  if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    process_ip(data + sizeof(ETH));
  else
    printf("???????\n");
}

void process_ip(const u_char *data)
{
  IP *iphdr = (IP *) data;
  print_ip_addr(iphdr->src, " -> ");
  print_ip_addr(iphdr->dst, " ");
  process_layers(iphdr->proto, data + sizeof(IP));
}

void process_layers(uint8_t proto, const u_char *data)
{
  switch (proto) {
    case IPPROTO_TCP:
      process_tcp(data);
      break;
    case IPPROTO_UDP:
      process_udp(data);
      break;
    case IPPROTO_ICMP:
      process_icmp(data);
      break;
    default:
      printf("[Unknown: %d]\n", proto);
      break;
  }
}

void process_tcp(const u_char *data)
{
  TCP *tcphdr = (TCP *) data;
  printf("[TCP] %d->%d\n", ntohs(tcphdr->src), ntohs(tcphdr->dst));
}

void process_udp(const u_char *data)
{
  UDP *udphdr = (UDP *) data;
  printf("[UDP] %d->%d\n", ntohs(udphdr->src), ntohs(udphdr->dst));
}

void process_icmp(const u_char *data)
{
  char *type_str = "";
  ICMP *icmphdr = (ICMP *) data;
  switch (icmphdr->type) {
    print_cases();
    default:
      type_str = "unknown";
      break;
  }
  printf("[ICMP] type=%s, code=%d\n", type_str, icmphdr->code);
}

void print_ip_addr(uint32_t addr, const char *end)
{
  char str[IP_ADDR_LEN+1] = { 0 };
  struct in_addr saddr = { 0 };
  saddr.s_addr = addr;
  inet_ntop(PF_INET, &saddr, str, sizeof(str));
  printf("%s%s", str, end);
}

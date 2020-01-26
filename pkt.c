/**
 * @Author: S. Sharma <m4rtyr>
 * @Date:   2020-01-24T20:25:01-06:00
 * @Email:  silentcat@protonmail.com
 * @Last modified by:   m4rtyr
 * @Last modified time: 2020-01-26T00:10:01-06:00
 */

#include "pkt.h"

int open_dev()
{
  int bpf = 0;
  char buf[BPF_DEVICE_NAME_LEN+1] = { 0 };
  for (int i = 0; i < BPF_DEVICES_COUNT; i++) {
    snprintf(buf, BPF_DEVICE_NAME_LEN+1, "/dev/bpf%i", i);
    bpf = open(buf, O_RDWR);
    if (bpf != -1)
      break;
  }
  return bpf;
}

const char *get_device_name()
{
  struct ifaddrs *ifap = NULL;
  check(getifaddrs(&ifap) == 0, "getifaddrs failed");
  const char *name = (const char *) ifap->ifa_name;
  freeifaddrs(ifap);
  return name;
error:
  return NULL;
}

int assoc_dev(int bpf, const char *device_name)
{
  int opt = 1;
  struct ifreq bound_if;
  memset(&bound_if, 0, sizeof(bound_if));
  if (strlen(device_name) < sizeof(bound_if.ifr_name))
    strncpy(bound_if.ifr_name, device_name, strlen(device_name));
  else
    strncpy(bound_if.ifr_name, device_name, sizeof(bound_if.ifr_name));
  check(ioctl(bpf, BIOCSETIF, &bound_if) == 0, "ioctl failed");
  check(ioctl(bpf, BIOCPROMISC) == 0, "ioctl failed");
  check(ioctl(bpf, BIOCIMMEDIATE, &opt) == 0, "ioctl failed");
  return SUCCESS;
error:
  return FAILURE;
}

int set_pkt_insn(int bpf)
{
  struct bpf_insn insns[] = {
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 7),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 23),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 3, 1),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP, 3, 1),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMP, 3, 0),
    BPF_STMT(BPF_RET+BPF_K,
      sizeof(ETH) + sizeof(IP) + sizeof(TCP)),
    BPF_STMT(BPF_RET+BPF_K,
      sizeof(ETH) + sizeof(IP) + sizeof(UDP)),
    BPF_STMT(BPF_RET+BPF_K,
      sizeof(ETH) + sizeof(IP) + sizeof(ICMP)),
    BPF_STMT(BPF_RET+BPF_K, 0)
  };

  struct bpf_program prog = { 0 };
  prog.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
  prog.bf_insns = insns;
  check(ioctl(bpf, BIOCSETFNR, &prog) == 0, "ioctl failed");
  return SUCCESS;
error:
  return FAILURE;
}

int set_up_socket()
{
  int bpf = open_dev();
  check_no_out(bpf != -1);
  const char *device_name = get_device_name();
  check_no_out(device_name != NULL);
  device_name = "en0";
  check_no_out(assoc_dev(bpf, device_name) == SUCCESS);
  check_no_out(set_pkt_insn(bpf) == SUCCESS);
  return bpf;
error:
  if (bpf != -1)
    close(bpf);
  return -1;
}

void event_loop()
{
  int bpf = set_up_socket(), buf_len = 0;
  char *buffer = NULL;

  check_no_out(bpf != -1);
  buffer = calloc(1, buf_len);
  check(ioctl(bpf, BIOCGBLEN, &buf_len) == 0, "ioctl failed");
  check_mem(buffer);
  sock = bpf;
  buff = buffer;
  while (1) {
    int bytes_read = read(bpf, buffer, buf_len);
    if (bytes_read >= 0) {
      process_pkt(bytes_read, buffer);
      memset(buffer, 0, buf_len);
    } else {
      break;
    }
  }
  return;
error:
  if (buffer) {
    free(buffer);
    buff = NULL;
  }
  close(bpf);
}

void process_pkt(int bytes_read, char *data)
{
  char *ptr = data;
  while (ptr < (data + bytes_read)) {
    struct bpf_hdr *hdr = (struct bpf_hdr *) ptr;
    printf("[%d] ", hdr->bh_tstamp.tv_sec);
    process_ether(ptr + hdr->bh_hdrlen);
    ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
  }
}

void process_ether(char *data)
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
  process_ip(data + sizeof(ETH));
}

void process_ip(char *data)
{
  char str[IP_ADDR_LEN+1] = { 0 };
  struct in_addr addr = { 0 };
  IP *iphdr = (IP *) data;
  addr.s_addr = iphdr->src;
  inet_ntop(PF_INET, &addr, str, sizeof(str));
  printf("%s -> ", str);
  addr.s_addr = iphdr->dst;
  memset(str, 0, IP_ADDR_LEN+1);
  inet_ntop(PF_INET, &addr, str, sizeof(str));
  printf("%s, ", str);
  process_layers(iphdr->proto, data + sizeof(IP));
}

void process_layers(uint8_t proto, char *data)
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

void process_tcp(char *data)
{
  TCP *tcphdr = (TCP *) data;
  printf("[TCP] %d->%d\n", ntohs(tcphdr->src), ntohs(tcphdr->dst));
}

void process_udp(char *data)
{
  UDP *udphdr = (UDP *) data;
  printf("[UDP] %d->%d\n", ntohs(udphdr->src), ntohs(udphdr->dst));
}

void process_icmp(char *data)
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

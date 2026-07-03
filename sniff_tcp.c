#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  // Ethernet 안이 IP가 아니면 무시
  if (ntohs(eth->ether_type) != 0x0800) {
    return;
  }

  struct ipheader *ip = (struct ipheader *)
                         (packet + sizeof(struct ethheader));

  // IP 안이 TCP가 아니면 무시
  if (ip->iph_protocol != IPPROTO_TCP) {
    return;
  }

  // IP 헤더 길이는 4바이트 단위로 저장되어 있으므로 4를 곱해준다
  int ip_header_len = ip->iph_ihl * 4;

  struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

  // TCP 헤더 길이도 마찬가지로 4를 곱해준다
  int tcp_header_len = TH_OFF(tcp) * 4;

  printf("=======================================================\n");

  // Ethernet Header
  printf("Ethernet Header\n");
  printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

  // IP Header
  printf("IP Header\n");
  printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
  printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

  // TCP Header
  printf("TCP Header\n");
  printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
  printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

  // 실제 메시지의 시작 위치와 길이 계산
  int eth_header_len = sizeof(struct ethheader);
  int header_total_len = eth_header_len + ip_header_len + tcp_header_len;

  int ip_total_len = ntohs(ip->iph_len);        // IP 패킷 전체 길이(헤더+데이터)
  int payload_len = ip_total_len - ip_header_len - tcp_header_len;

  if (payload_len > 0) {
    const u_char *payload = packet + header_total_len;

    printf("Message (%d bytes)\n", payload_len);

    // 캡처된 실제 데이터보다 더 읽으면 안되므로 header->caplen과 비교
    int available = header->caplen - header_total_len;
    int print_len = payload_len < available ? payload_len : available;

    for (int i = 0; i < print_len; i++) {
      // 출력 가능한 문자면 그대로, 아니면 . 으로 표시
      if (payload[i] >= 32 && payload[i] < 127)
        putchar(payload[i]);
      else
        putchar('.');
    }
    printf("\n");
  } else {
    printf("Message: (no payload)\n");
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";   // TCP만 캡처
  bpf_u_int32 net;

  // 네트워크 이름 확인하기
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    pcap_perror(handle, "Error compiling filter");
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) != 0) {
    pcap_perror(handle, "Error setting filter");
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;
}

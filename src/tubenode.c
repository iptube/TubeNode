
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO

#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <stunlib.h>


// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length
#define UDP_HDRLEN 8





static void printPkt(struct ip *ip_pkt){
    printf("%s", inet_ntoa(ip_pkt->ip_src));
    printf("->%s ", inet_ntoa(ip_pkt->ip_dst));
    printf("(TTL: %i, ", ip_pkt->ip_ttl);
    printf("len: %hu)\n", ntohs( ip_pkt->ip_len));

}



static int Callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *cbData)
{
    printf("Got a SPUD packet from netfilter\n");
    uint32_t id = 0;
    uint32_t pkt_size;
    char *pktData;
    struct ip *ip_pkt;
    
    
    StunMessage stunPkt;
    
    struct nfqnl_msg_packet_hdr *header;
    if ((header = nfq_get_msg_packet_hdr(pkt))) {
        id = ntohl(header->packet_id);
    }
    pkt_size = nfq_get_payload(pkt, &pktData);
    ip_pkt = (struct ip *)pktData;
    
    printf("Got SPUD\n");
    
    printPkt(ip_pkt);
    
    return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
  struct nfq_handle *nfqHandle;

  struct nfq_q_handle *myQueue;
  struct nfnl_handle *netlinkHandle;

  int fd, res;
  char buf[4096] __attribute__((aligned));

  if (!(nfqHandle = nfq_open())) {
    perror("nfq_open");
    exit(1);
  }

  if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
    perror("nfq_unbind_pf");
    exit(1);
  }

  if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
    perror("nfq_bind_pf");
    exit(1);
  }

  if (!(myQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
    perror("nfq_create_queue");
    exit(1);
  }

  if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
    perror("nfq_set_mode");
    exit(1);
  }

  netlinkHandle = nfq_nfnlh(nfqHandle);
  fd = nfnl_fd(netlinkHandle);

  printf("Up and running, waiting for packets...\n\n");
  while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
    nfq_handle_packet(nfqHandle, buf, res);
  }

  nfq_destroy_queue(myQueue);

  nfq_close(nfqHandle);

  return 0;
}


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



static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *cbData)
{
    struct nfqnl_msg_packet_hdr *ph;
    int id = 0;
    int size = 0;
    int i;
    unsigned char *full_packet;
    unsigned char * c;
    struct iphdr *ip;
    struct in_addr ipa;
    char src_ip_str[20];
    char dst_ip_str[20];

    ph = nfq_get_msg_packet_hdr(nfa);
 
    if (ph) {
  
        // Print out metatdata
        id = ntohl(ph->packet_id);
        fprintf(stdout, "hw_protocol = 0x%04x hook = %u id = %u\n",
                ntohs(ph->hw_protocol), ph->hook, id);

        // Retrieve packet payload
        size = nfq_get_payload(nfa, &full_packet);  

        // Get IP addresses in char form
        ip = (struct iphdr *) full_packet;
        ipa.s_addr=ip->saddr;
        strcpy (src_ip_str, inet_ntoa(ipa));
        ipa.s_addr=ip->daddr;
        strcpy (dst_ip_str, inet_ntoa(ipa));

        fprintf(stdout, "Source IP: %s   Destination IP: %s\n", src_ip_str, dst_ip_str);

        // Print out packet in hex
        c = (unsigned char *)full_packet;
        for (i=0; i<size; ++i,++c) {
            fprintf (stdout, "%02x", (unsigned int)*c);
        }
        fprintf (stdout, "\n");

        // Done with packet, accept it
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    return 0;

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
      //printf("Got somthing in the queue\n");
      nfq_handle_packet(nfqHandle, buf, res);

  }

  printf("Should I be here?\n");
  nfq_destroy_queue(myQueue);

  nfq_close(nfqHandle);

  return 0;
}

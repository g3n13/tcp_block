#include <libnet.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define SIZE_ETHERNET 14

#pragma pack(push,1)
typedef struct ethhdr
{
        uint8_t ether_dhost[6];
        uint8_t ether_shost[6];
        uint16_t ether_type;
}ethhdr;
#pragma pack(pop)

u_short ip_sum_calc(u_short len_ip_header, u_short * buff )
{
        u_short word16;
        u_int sum = 0;
        u_short i;
        
	for( i = 0; i < len_ip_header; i = i+2 )
        {
                word16 = ( ( buff[i]<<8) & 0xFF00 )+( buff[i+1] & 0xFF );
                sum = sum + (u_int) word16;
        }
        while( sum >> 16 )
                sum = ( sum & 0xFFFF ) + ( sum >> 16 );
        sum = ~sum;
       
        return ((u_short) sum);
}

struct pseudo_header{
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
};

uint16_t tcp_check(uint16_t *ptr,int nbytes) {
        register long sum;
        unsigned short oddbyte;
        register short answer;
 
        sum=0;
        while(nbytes>1) {
                sum+=*ptr++;
                nbytes-=2;
        }
        if(nbytes==1) {
                oddbyte=0;
                *((uint8_t*)&oddbyte)=*(uint8_t*)ptr;
                sum+=oddbyte;
        }
 
        sum = (sum>>16)+(sum & 0xffff);
        sum = sum + (sum>>16);
        answer=(uint16_t)~sum;
       
        return(answer);
}

int main(int argc, char* argv[]) {
  
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    struct ethhdr* ether_hdr;
    struct libnet_ipv4_hdr* ip_hdr;
    struct libnet_tcp_hdr* t_hdr;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    unsigned char *payload;
    uint8_t* s_mac=(uint8_t*)malloc(6*sizeof(uint8_t));
    uint8_t* t_mac=(uint8_t*)malloc(6*sizeof(uint8_t));
    char* ip_src_str;
    char* ip_dst_str;
    u_int tcp_sport;
    u_int tcp_dport;
    int tmp;
    uint8_t* tmp_char;

    u_int size_ip;
    u_short size_tcp;
    int size;
    
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    //ethernet
    ether_hdr = (struct ethhdr*)(packet);
    if(ether_hdr != NULL && ntohs(ether_hdr->ether_type) == 0x0800)
    {
	memcpy(s_mac, ether_hdr->ether_shost, 6*sizeof(uint8_t));
	memcpy(t_mac, ether_hdr->ether_dhost, 6*sizeof(uint8_t));
    }
    else
	continue;
    
    //ip
    ip_hdr = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
    if(ip_hdr!=NULL && ip_hdr->ip_p == 0x06)
    {
    	size_ip = (ip_hdr->ip_hl)*4;
    	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return -1;
    	}
	//ip_checksum
	ip_hdr->ip_sum=0;
	uint16_t ipdata[20];
	for(int i=0;i<20;i++)ipdata[i]=*(uint8_t*)ip_hdr++;
	ip_hdr->ip_sum=htons(ip_sum_calc(20,ipdata));
    }
    else
	continue;

    //tcp
    t_hdr = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
    if(t_hdr!=NULL)
    {
    	size_tcp = (t_hdr->th_off)*4;
        tcp_sport = ntohs(t_hdr->th_sport);
        tcp_dport = ntohs(t_hdr->th_dport);
    	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return -1;
    	}

	t_hdr->th_flags = 0b000010100;
	t_hdr->th_win = 0x0;
	printf("flags : %d\n", t_hdr->th_flags);

	size = SIZE_ETHERNET+size_ip+size_tcp;
	uint8_t* s_packet = (uint8_t*)malloc(size*sizeof(uint8_t));
	printf("%d\n", size);

	//tcp_checksum
	t_hdr->th_sum=0;
	struct pseudo_header *psh=(struct pseudo_header*)malloc(sizeof(struct pseudo_header));
	psh->source_address=inet_addr(inet_ntoa(ip_hdr->ip_src));
	psh->dest_address=inet_addr(inet_ntoa(ip_hdr->ip_dst));
	psh->placeholder=0;//reserved
	psh->protocol=6;//protocol number for tcp
	psh->tcp_length=htons(size_tcp);
	
	uint8_t *seudo=(uint8_t*)malloc(sizeof(struct pseudo_header)+size_tcp);
	memcpy(seudo,psh,sizeof(struct pseudo_header));
	memcpy(seudo+sizeof(struct pseudo_header),t_hdr,size_tcp);
	uint16_t checksum=tcp_check((uint16_t*)seudo,sizeof(struct pseudo_header)+size_tcp);
	t_hdr->th_sum=checksum;

	memcpy(ether_hdr + SIZE_ETHERNET + size_ip, t_hdr, size_tcp);
	
	//new packet-change only flag
	memcpy(s_packet, ether_hdr, size*sizeof(uint8_t));
	
	/*for(int i=0;i<size;i++)
		printf("%02x ", s_packet[i]);*/
	
	if(pcap_sendpacket(handle, s_packet, size))
        {
                printf("Failed send packet\n");
                return -1;
        }
	
	//new packet2-change src & dst
	memcpy(ether_hdr->ether_shost, t_mac, 6*sizeof(uint8_t));
	memcpy(ether_hdr->ether_dhost, s_mac, 6*sizeof(uint8_t));
	struct in_addr addr = ip_hdr->ip_src;
	ip_hdr->ip_src = ip_hdr->ip_dst;
	ip_hdr->ip_dst = addr;
	t_hdr->th_sport = htons(tcp_dport);
	t_hdr->th_dport = htons(tcp_sport);
	tmp = t_hdr->th_seq;
	t_hdr->th_seq = t_hdr->th_ack;
	t_hdr->th_ack = tmp;

	//ip_checksum
        ip_hdr->ip_sum=0;
        uint16_t ipdata[20];
        for(int i=0;i<20;i++)ipdata[i]=*(uint8_t*)ip_hdr++;
        ip_hdr->ip_sum=htons(ip_sum_calc(20,ipdata));

	//tcp_checksum
        t_hdr->th_sum=0;
        psh->source_address=inet_addr(inet_ntoa(ip_hdr->ip_src));
	psh->dest_address=inet_addr(inet_ntoa(ip_hdr->ip_dst));
        psh->placeholder=0;//reserved
        psh->protocol=6;//protocol number for tcp
        psh->tcp_length=htons(size_tcp);

        memcpy(seudo,psh,sizeof(struct pseudo_header));
        memcpy(seudo+sizeof(struct pseudo_header),t_hdr,size_tcp);
        checksum=tcp_check((uint16_t*)seudo,sizeof(struct pseudo_header)+size_tcp);
        t_hdr->th_sum=checksum;

	memcpy(s_packet, ether_hdr, size*sizeof(uint8_t));
	
	if(pcap_sendpacket(handle, s_packet, size))
        {
                printf("Failed send packet\n");
                return -1;
        }
	
	continue;
    }
    else
	continue;

    //HTTP?
    payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    int i=0;
    if(payload[i]!='\0')
    {
	for(i=0;i<16;i++)
		printf("%02x ", payload[i]);
    }
    printf("\n\n");
    printf("---------------------------------\n\n");
  }

  pcap_close(handle);
  return 0;
}

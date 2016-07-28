/*
 * sniffer.c
 * 
 * This is a modification of David C Harrison's (david.harrison@ecs.vuw.ac.nz) original sniffer.c July 2015 
 * 
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap 
 *
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
 */

#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>


int count = 0;

//function from http://www.tcpdump.org/sniffex.c
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
//function from http://www.tcpdump.org/sniffex.c
/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void tcp(const u_char *packet, unsigned int currentLength,uint16_t payloadLength){
	struct tcphdr *tcpHeader = (struct tcphdr*)packet;
	printf("Source Port: %d\n", ntohs(tcpHeader->th_sport));
	printf("Destination Port: %d\n",ntohs(tcpHeader->th_dport));
	int tcpHeaderSize = tcpHeader->doff*4;
	unsigned int dataSize = currentLength - tcpHeaderSize;
	if(currentLength==0){
		dataSize = payloadLength;
	} else{
		dataSize = currentLength - tcpHeaderSize;
	}
	

	printf("Payload: %d\n", dataSize);
	print_payload(packet+tcpHeaderSize,dataSize);
	

	//packet+(tcpHeader->thoff);
}

void protocol(const u_char *packet, u_int8_t protocol, unsigned int currentLength, uint16_t payloadLength){
	//protocol definitions from http://www.tcpdump.org/sniffex.c
	if(protocol==IPPROTO_ICMP){
		printf("Protocol: ICMP\n");
	} else if(protocol==IPPROTO_TCP){
		printf("Protocol: TCP\n");
		tcp(packet, currentLength,payloadLength);
	} else if(protocol==IPPROTO_UDP){
		printf("Protocol: UDP\n");
	}

	
}

void ip6Header(const u_char *packet){
	struct ip6_hdr *ip6Head = (struct ip6_hdr*)packet;
	
	struct in6_addr srcAdd = ip6Head->ip6_src;   	/* source address */
    struct in6_addr dstAdd = ip6Head->ip6_dst;	/* destination address */
	

	//code for printing out ipv6
	/**
		http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
		https://github.com/shreyasrama/ethernet-packet-sniffer/blob/master/sniffer.c
	**/
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &srcAdd, src, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &dstAdd, dst, INET6_ADDRSTRLEN);
	printf("From: %s\n",src);
	printf("To: %s\n",dst);

	struct ip6_hdrctl *ip6Headctl = (struct ip6_hdrctl*)packet;

	u_int8_t ip6_protocol = ip6Headctl->ip6_un1_nxt;
	uint16_t payloadLength = ntohs(ip6Headctl->ip6_un1_plen);   /* payload length */
	int ip6HeadSize = sizeof(struct ip6_hdr);

	protocol(packet+ip6HeadSize, ip6_protocol, 0,payloadLength);




	//printf("Next header: %d", ip6Head->ip6_un1_nxt);

	//printf("From: %s\n",inet_ntop(src));
	//printf("To: %s\n",inet_ntop(dst));
	//protocol(packet+sizeof(struct ip6_hdr))
	//printf("Size of ipv6 header: %d\n",sizeof(struct ip6_hdr));




	/*
	https://github.com/shreyasrama/ethernet-packet-sniffer/blob/master/sniffer.c
		// Prints details of an IPv6 header.
void print_ipv6_header(struct ipv6* ipv6_header) {
	char srcaddr[32];
	char dstaddr[32];
	inet_ntop(AF_INET6, &ipv6_header->ip_src, srcaddr, sizeof(srcaddr)); // inet_ntop() takes a binary address (both IP versions) and returns in text form
	inet_ntop(AF_INET6, &ipv6_header->ip_dst, dstaddr, sizeof(dstaddr));
	printf("From: %s\n", srcaddr);
	printf("To: %s\n", dstaddr);
	printf("Protocol: %s\n", get_protocol_name(ipv6_header->next_header));
}

	*/
}

void ipHeader(const u_char *packet){
	struct ip *ipHead = (struct ip*)packet;
	struct in_addr src = ipHead->ip_src;
	struct in_addr dst = ipHead->ip_dst;
	printf("From: %s\n",inet_ntoa(src));
	printf("To: %s\n",inet_ntoa(dst));
	
	//tot length = ipHeader + Layer 3 protocol header + data payload
	//Need this for calculating size of data payload
	u_short totLength = ntohs(ipHead->ip_len);
	//printf("tot Length: %d",totLength);
	unsigned int ipHeaderSize = ipHead->ip_hl*4;
	//printf("ip Header size: %d",ipHeaderSize);

	//current Length = Layer 3 protocol header + data payload
	unsigned int currentLength = totLength - ipHeaderSize;
	//printf("current Length: %d",currentLength);
	protocol(packet+ipHeaderSize, ipHead->ip_p, currentLength,0);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	char *hex;
	//used struct casting and using ntohs to compare the types
	//http://yuba.stanford.edu/~casado/pcap/section2.html

	struct ether_header *etherheader;
	
	etherheader = (struct ether_header *)packet;

	//size of the ether header
	int etherHeadSize = sizeof(struct ether_header);

	printf("\nPacket #: %d\n",++count);
	if(ntohs(etherheader->ether_type) == ETHERTYPE_IP){
		printf("Ether Type: IPv4\n");
		
		ipHeader((packet+etherHeadSize));
	} else if(ntohs(etherheader->ether_type) == ETHERTYPE_IPV6){
		printf("Ether Type: IPv6\n");
		
		//ipv6 header 
		ip6Header(packet + etherHeadSize);
	} if(ntohs(etherheader->ether_type) == ETHERTYPE_ARP){
		printf("Ether Type: ARP\n");
	}

	// hex = ("lol%08X",etherheader->ether_dhost);
	// printf(hex);
	// printf("From: %08X\n",etherheader->ether_dhost);
	// printf("To: %x\n",etherheader->ether_shost);
	// printf("packet type: %d\n", etherheader->ether_type);
	// printf("Ether types %d ", ETHERTYPE_IP);

    //printf("\n Header Length: %d\n", header->len);
}



int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }

    pcap_t *handle = pcap_open_offline(argv[1], NULL);
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle); 
    return 0;
}

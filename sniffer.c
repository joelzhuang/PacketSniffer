/*
 * sniffer.c
 * 
 * This is a modification of David C Harrison's (david.harrison@ecs.vuw.ac.nz) original sniffer.c July 2015 
 * Author of modification: Joely Huang (300305742)
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
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
 #include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>


//counter needed to count number of packets
int count = 0;

//function from http://www.tcpdump.org/sniffex.c
//need funtion to print payload 
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

void tcp(const u_char *packet, unsigned int currentLength){
	struct tcphdr *tcpHeader = (struct tcphdr*)packet;

	//ntohs need to flip bits to get ports
	printf("Source Port: %d\n", ntohs(tcpHeader->th_sport));
	printf("Destination Port: %d\n",ntohs(tcpHeader->th_dport));
	
	//tcp header size, multiply by 4 due to 4 rows(words).
	int tcpHeaderSize = tcpHeader->doff*4;

	//current payload - tcp header sizse
	unsigned int dataSize = currentLength - tcpHeaderSize;
	
	

	printf("Payload: %d (bytes)\n", dataSize);
	print_payload(packet+tcpHeaderSize,dataSize);
	
}

void udp(const u_char *packet){
	struct udphdr *udpHeader = (struct udphdr*)packet;

	printf("Source Port: %d\n", ntohs(udpHeader->uh_sport));
	printf("Destination Port: %d\n",ntohs(udpHeader->uh_dport));

	//standard udp header size
	int udpHeaderSize = sizeof(struct udphdr);
	//need to minus updHeaderSize for length to get dataSize
	int dataSize = ntohs(udpHeader->uh_ulen)-udpHeaderSize;
	printf("Payload: %d (bytes)\n ", dataSize);
	print_payload(packet+udpHeaderSize,dataSize);


}

void icmp(const u_char *packet,unsigned int currentLength){
	struct icmphdr *icmpHeader = (struct icmphdr*)packet;

	//standard udp header size
	int icmpHeaderSize = sizeof(struct icmphdr);
	//current length - 8 bytes (data error)
	int dataSize = currentLength - icmpHeaderSize;

	//getting the icmp message type
	int type = icmpHeader->type;
	if(type==ICMP_ECHO){
		printf("Type: Echo Request\n");
	} else if(type==ICMP_ECHOREPLY){
		printf("Type: Echo Reply\n");
	} else if(type==ICMP_DEST_UNREACH){
		printf("Type: Destination Unreachable\n");
	} else if(type==ICMP_SOURCE_QUENCH){
		printf("Type: Source Quench\n");
	} else if(type==ICMP_REDIRECT){
		printf("Type: Redirect\n");
	} else if(type==ICMP_TIME_EXCEEDED){
		printf("Type: Time Exceeded\n");
	} else if(type==ICMP_PARAMETERPROB){
		printf("Type: Parameter Problem\n");
	} else if(type==ICMP_TIMESTAMP){
		printf("Type: Timestamp Request\n");
	} else if(type==ICMP_TIMESTAMPREPLY){
		printf("Type: Timestamp Reply\n");
	} else if(type==ICMP_INFO_REQUEST){
		printf("Type: Information Request\n");
	} else if(type==ICMP_INFO_REPLY){
		printf("Type: Information Reply\n");
	} else if(type==ICMP_ADDRESS){
		printf("Type: Address Mask Request\n");
	} else if(type==ICMP_ADDRESSREPLY){
		printf("Type: Address Mask Reply\n");
	} 


	printf("Payload: %d (bytes)\n ", dataSize);
	print_payload(packet+icmpHeaderSize,dataSize);


}

void icmp6(const u_char *packet, unsigned int currentLength){
	struct icmp6_hdr *icmp6Header = (struct icmp6_hdr*)packet;

	int icmp6HeaderSize = sizeof(struct icmp6_hdr);
	int dataSize = currentLength - icmp6HeaderSize;

	uint8_t type = icmp6Header->icmp6_type;

	//getting the icmpv6 type
	if(type==ICMP6_ECHO_REQUEST){
		printf("Type: Echo Request\n");
	} else if(type==ICMP6_ECHO_REPLY){
		printf("Type: Echo Reply\n");
	} else if(type==ICMP6_DST_UNREACH_NOROUTE){
		printf("Type: Destination Unreachable\n");
	} else if(type==ICMP6_DST_UNREACH_ADMIN){
		printf("Type: Communication with destination administratively prohibited\n");
	} else if(type==ICMP6_DST_UNREACH_BEYONDSCOPE){
		printf("Type: Beyond scope of source address\n");
	} else if(type==ICMP6_DST_UNREACH_ADDR){
		printf("Type: Address unreachable\n");
	} else if(type==ICMP6_DST_UNREACH_NOPORT){
		printf("Type: Bad port\n");
	} 

	printf("Payload: %d (bytes)\n ", dataSize);
	print_payload(packet+icmp6HeaderSize,dataSize);
}

void protocol(const u_char *packet, u_int8_t protocol, unsigned int currentLength){
	//protocol definitions from http://www.tcpdump.org/sniffex.c
	
	if(protocol==IPPROTO_ICMPV6){
		printf("Protocol: ICMPv6\n");
		icmp6(packet,currentLength);
	} else if(protocol==IPPROTO_ICMP){
		printf("Protocol: ICMP\n");
		icmp(packet,currentLength);
	} else if(protocol==IPPROTO_TCP){
		printf("Protocol: TCP\n");
		tcp(packet, currentLength);
	} else if(protocol==IPPROTO_UDP){
		printf("Protocol: UDP\n");
		udp(packet);
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

	//converting to ip address:
	inet_ntop(AF_INET6, &srcAdd, src, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &dstAdd, dst, INET6_ADDRSTRLEN);

	printf("From: %s\n",src);
	printf("To: %s\n",dst);

	
	//getting details of ipv6 header:
	u_int8_t ip6_protocol = ip6Head->ip6_nxt;
	int payloadLength = ntohs(ip6Head->ip6_plen);   /* payload length */
	int ip6HeadSize = sizeof(struct ip6_hdr);

	//Extension header types
	if(ip6_protocol==IPPROTO_HOPOPTS){
		printf("Extension Header: Hop by Hop\n");
	} else if(ip6_protocol==IPPROTO_ROUTING	){
		printf("Extension Header: Routing Header\n");
	} else if(ip6_protocol==IPPROTO_FRAGMENT){
		printf("Extension Header: Fragmentation Header\n");
	} else if(ip6_protocol==IPPROTO_ICMPV6){
		printf("Extension Header: ICMPv6\n");
	} else if(ip6_protocol==IPPROTO_NONE){
		printf("Extension Header: No Next Header\n");
	} else if(ip6_protocol==IPPROTO_DSTOPTS){
		printf("Extension Header: IPv6 destination options\n");
	} else if(ip6_protocol==IPPROTO_MH){
		printf("Extension Header: IPv6 mobility header\n");
	} 

	//finding next protocol 
	protocol(packet+ip6HeadSize, ip6_protocol, payloadLength);
}

void ipHeader(const u_char *packet){
	struct ip *ipHead = (struct ip*)packet;
	struct in_addr src = ipHead->ip_src;
	struct in_addr dst = ipHead->ip_dst;

	//using inet_ntoa to get ip address
	//http://beej.us/guide/bgnet/output/html/multipage/inet_ntoaman.html
	printf("From: %s\n",inet_ntoa(src));
	printf("To: %s\n",inet_ntoa(dst));
	
	//tot length = ipHeader + Layer 3 protocol header + data payload
	//Need this for calculating size of data payload
	u_short totLength = ntohs(ipHead->ip_len);
	
	//multiply by 4 to get size of header as there are four rows
	unsigned int ipHeaderSize = ipHead->ip_hl*4;


	//current Length = Layer 3 protocol header + data payload
	unsigned int currentLength = totLength - ipHeaderSize;
	
	//going to next layer and finding protocol
	protocol(packet+ipHeaderSize, ipHead->ip_p, currentLength);
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
		
		//ipv4 Header
		ipHeader((packet+etherHeadSize));
	} else if(ntohs(etherheader->ether_type) == ETHERTYPE_IPV6){
		printf("Ether Type: IPv6\n");
		
		//ipv6 header 
		ip6Header(packet + etherHeadSize);
	} else {
		//unknown header, just prints out decimal
		printf("Ether Type: Unknown %d \n",ntohs(etherheader->ether_type));
	}
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

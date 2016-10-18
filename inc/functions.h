#define TRUE 1
#define FALSE 0
#define DOES_NOT_EXIST -1
#define SIZE_ETHERNET 14

typedef struct
{
  unsigned char* packet_counter2;
} myparams;

struct sniff_ip {
	u_char ip_vhl;      /* version << 4 | header length >> 2 */
	u_char ip_tos;      /* type of service */
	u_short ip_len;     /* total length */
	u_short ip_id;      /* identification */
	u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	u_char ip_ttl;      /* time to live */
	u_char ip_p;        /* protocol */
	u_short ip_sum;     /* checksum */
	struct in_addr ip_src;
	struct in_addr ip_dst; /* source and dest address */
};

typedef struct
{
	char IPaddressChar[100];
	long int sumPacketSize;
}PacketList;

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header,  struct ether_header *eth_header, struct ip *ip);
signed int does_this_packet_exists_for_time_slot(const u_char *packet, unsigned long int packetCounterForTimeSlot, PacketList* IPtable, struct ip *ip);
void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet);
void sort_packet_table(unsigned long int packetCounter, PacketList* packetTable);

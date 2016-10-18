#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "../inc/functions.h"

int main(int argc, char **argv)
{
  char error_buffer[PCAP_ERRBUF_SIZE] = "No Error\n";
  const u_char *packet;
  pcap_t *handle;
  struct pcap_pkthdr packet_header;
  unsigned long int packet_counter = 0;

  if(argc != 2)
  {
	  printf("WRONG ARGUMENT - Give the path to a pcap file as an argument\nEXAMPLE: ./GiveStatusIPpacketsReceived /home/usrname/pcaphome.pcap\n");
	  return 0;
  }

  handle = pcap_open_offline(argv[1], error_buffer);

  printf("Opening pcap file status: %s\n", error_buffer);
  if(strcmp("No Error\n", error_buffer) != 0)
  {
	  printf("ERROR unable to open the file\n");
	  return 0;
  }

  // Get the number of packet in contained in the file
  while(packet = pcap_next(handle, &packet_header))
  {
     packet_counter++;
  }
  printf("There is a total of %lu packet(s) contained by the file\n", packet_counter);

  // Reinitialize the handle
  handle = pcap_open_offline(argv[1], error_buffer);

  pcap_loop(handle, 0, my_packet_handler, &packet_counter);

  return 0;
}

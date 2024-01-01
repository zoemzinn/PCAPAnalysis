/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022

    Implemented By:     Zoe Zinn
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE *pcapInput = NULL; // The input PCAP file

bool bytesOK; // Does the capturer's byte ordering same as mine?
              // Affects the global PCAP header and each packet's header

bool microSec; // is the time stamp in Sec+microSec ?  or is it Sec+nanoSec

double baseTime; // capturing time of the very 1st packet in this file

bool baseTimeSet = false;

uint32_t cap_len; // length value used to get AppData for TCP packets

// New for Project 3:

arpmap_t myARPmap[MAXARPMAP]; // List of my IP addresses and their MACs

int mapSize = 0; // Number of mapping pairs read into myARPmap

FILE *pcapOutput = NULL; // The output PCAP file

uint16_t identification = 1000 ; // The id incremented for each ICMP response packet

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
void
errorExit (char *str)
{
  if (str)
    puts (str);
  if (pcapInput)
    fclose (pcapInput);
  exit (EXIT_FAILURE);
}

/*-------------------------------------------------------------------------*/
void
cleanUp ()
{
  if (pcapInput)
    fclose (pcapInput);
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname'
    and read its global header into buffer 'p'
    Side effects:
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */
int
readPCAPhdr (char *fname, pcap_hdr_t *p)
{
  // Opening PCAP file:
  FILE *file = fopen (fname, "r");
  if (!file)
    {
      fclose (file);
      return -1;
    }
  pcapInput = file;

  // Determine the capturer's byte ordering
  // Issue: magic_number could also be 0xa1b23c4D to indicate nano-second
  // resolution instead of microseconds. This affects the interpretation
  // of the ts_usec field in each packet's header.

  // Reading bytes into pcap_hdr_t struct:
  int read = fread (p, 1, sizeof (*p), pcapInput);
  if (read != sizeof (*p))
    {
      return -1;
    }

  // Checking magic number types:
  switch (p->magic_number)
    {
    // Big endian, microseconds
    case 0xa1b2c3d4:
      bytesOK = true;
      microSec = true;
      break;

    // Big endian, nanoseconds
    case 0xa1b23c4d:
      bytesOK = true;
      microSec = false;
      break;

    // Little endian, microseconds
    case 0xd4c3b2a1:
      bytesOK = false;
      microSec = true;
      break;

    // Little endian, nanoseconds
    case 0x4d3cb2a1:
      bytesOK = false;
      microSec = false;
      break;

    // Other
    default:
      return -1;
    }

  // Reordering the bytes of the PCAP header:
  if (!bytesOK)
    {
      p->version_major = ntohs (p->version_major);
      p->version_minor = ntohs (p->version_minor);
      p->thiszone = ntohl (p->thiszone);
      p->sigfigs = ntohl  (p->sigfigs);
      p->snaplen = ntohl  (p->snaplen);
      p->network = ntohl  (p->network);
    }

  return 0;
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void
printPCAPhdr (const pcap_hdr_t *p)
{
  printf ("magic number %X\n", p->magic_number);
  printf ("major version %d\n", p->version_major);
  printf ("minor version %d\n", p->version_minor);
  printf ("GMT to local correction %d seconds\n", p->thiszone);
  printf ("accuracy of timestamps %d\n", p->sigfigs);
  printf ("Cut-off max length of captured packets %d\n", p->snaplen);
  printf ("data link type %d\n", p->network);
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame)
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload

    If this is the very first packet from the PCAP file, set the baseTime

    Returns true on success, or false on failure for any reason

*/
bool
getNextPacket (packetHdr_t *p, uint8_t ethFrame[])
{
  // Checking for incoming NULL pointers
  int read = fread (p, 1, sizeof (*p), pcapInput);
  if (read != sizeof (*p))
    {
      return false; // There is no more packet headers
    }

  // Did the capturer use a different
  // byte-ordering than mine (as determined by the magic number)
  if (!bytesOK)
    {
      // Reordering the bytes of the fields in this packet header
      p->ts_sec   = ntohl (p->ts_sec);
      p->ts_usec  = ntohl (p->ts_usec);
      p->incl_len = ntohl (p->incl_len);
      p->orig_len = ntohl (p->orig_len);
    }

  // Reading the 'incl_len' bytes from the PCAP file into the ethFrame[]
  read = fread (ethFrame, 1, p->incl_len, pcapInput);
  if (read != p->incl_len)
    {
      return false;
    }
  cap_len = p->incl_len;

  // If necessary, set the baseTime
  if (!baseTimeSet)
    {
      baseTime = (double)p->ts_sec;
      double usec = (double)p->ts_usec;

      if (microSec)
        {
          usec /= 1000000;
        }
      else
        {
          usec /= 1000000000;
        }
      baseTime += usec;
      baseTimeSet = true;
    }

  return true;
}

/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length

*/
void
printPacketMetaData (const packetHdr_t *p)
{
  // Calculating relative capture time
  double curr_time = (double)p->ts_sec;
  double usec = (double)p->ts_usec;
  if (microSec)
    {
      usec /= 1000000;
    }
  else
    {
      usec /= 1000000000;
    }
  curr_time += usec;

  double timestamp = curr_time - baseTime;

  // Printing
  printf ("%15.6f %5d / %5d ", timestamp, p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy
   Recall that all multi-byte data is in Network-Byte-Ordering

*/
void
printPacket (const etherHdr_t *frPtr)
{
  uint16_t ethType = ntohs (frPtr->eth_type);
  char buf[64];

  switch (ethType)
    {
    case PROTO_ARP: // Print ARP message
      memset (buf, 0, sizeof (buf));

      // Source
      memset (buf, 0, sizeof (buf));
      printf ("%s    ", macToStr (frPtr->eth_srcMAC, buf, sizeof (buf)));

      // Destination
      memset (buf, 0, sizeof (buf));
      printf ("%s    ", macToStr (frPtr->eth_dstMAC, buf, sizeof (buf)));

      printARPinfo ((arpMsg_t *)(frPtr + 1));
      return;

    case PROTO_IPv4: // Print IP datagram and upper protocols
      printIPinfo ((ipv4Hdr_t *)(frPtr + 1));
      return;

    default:
      memset (buf, 0, sizeof (buf));

      // Source
      memset (buf, 0, sizeof (buf));
      printf ("%s    ", macToStr (frPtr->eth_srcMAC, buf, sizeof (buf)));

      // Destination
      memset (buf, 0, sizeof (buf));
      printf ("%s    ", macToStr (frPtr->eth_dstMAC, buf, sizeof (buf)));

      printf ("Protocol %x Not Supported Yet", ethType);
      return;
    }
}

/*-------------------------------------------------------------------------*/
/* Print ARP messages
   Recall that all multi-byte data is in Network-Byte-Ordering

*/
void
printARPinfo (const arpMsg_t *p)
{
  char buf[64];
  memset (buf, 0, sizeof (buf));

  // Protocol
  printf ("%-8s ", "ARP");

  switch (ntohs (p->arp_oper))
    {
    case ARPREQUEST:
      printf ("Who has %s ? ", ipToStr (p->arp_tpa, buf));
      memset (buf, 0, sizeof (buf));
      printf ("Tell %s", ipToStr (p->arp_spa, buf));
      break;

    case ARPREPLY:
      printf ("%s is at ", ipToStr (p->arp_spa, buf));
      memset (buf, 0, sizeof (buf));
      printf ("%s ", macToStr (p->arp_sha, buf, sizeof (buf)));
      break;

    default:
      printf ("Invalid ARP Operation %4x", p->arp_oper);
      break;
    }
}

/*-------------------------------------------------------------------------*/
/* Print IP datagram and upper protocols
   Recall that all multi-byte data is in Network-Byte-Ordering

*/
void
printIPinfo (const ipv4Hdr_t *q)
{

  void *nextHdr;
  icmpHdr_t *ic;
  unsigned ipHdrLen, ipPayLen, dataLen = 0;

  // 'dataLen' is the number of bytes in the payload of the encapsulated
  // protocol without its header. For example, it could be the number of bytes
  // in the payload of the encapsulated ICMP message

  char buf[64];
  memset (buf, 0, sizeof (buf));

  // Source
  printf ("%-21s", ipToStr (q->ip_srcIP, buf));
  memset (buf, 0, sizeof (buf));

  // Destination
  printf ("%-21s", ipToStr (q->ip_dstIP, buf));

  switch (q->ip_proto)
    {
    case PROTO_ICMP:
      printf ("%-8s ", "ICMP");

      // Print IP header length and numBytes of the options
      ipHdrLen = (q->ip_verHlen & 0b00001111) * 4;

      printf ("IPhdr=%02d (Options %d bytes)", ipHdrLen, ipHdrLen - 20);

      // Print the details of the ICMP message by calling printICMPinfo( ic )
      unsigned icmpHdrLen = printICMPinfo ((icmpHdr_t *)(q + (ipHdrLen / 20)));

      // Compute 'dataLen' : the length of the data section inside the ICMP
      // message
      dataLen = ntohs (q->ip_totLen) - (icmpHdrLen + ipHdrLen);
      break;

    case PROTO_TCP:
      printf ("%-8s ", "TCP");

      // Print IP header length and numBytes of the options
      ipHdrLen = (q->ip_verHlen & 0b00001111) * 4;

      printf ("IPhdr=%02d (Options %d bytes)", ipHdrLen, dataLen);

      dataLen = printTCPinfo ((tcpHdr_t *)(q + 1));

      break;

    case PROTO_UDP:
      printf ("%-8s ", "UDP");

      // Print IP header length and numBytes of the options
      ipHdrLen = (q->ip_verHlen & 0b00001111) * 4;

      printf ("IPhdr=%02d (Options %d bytes)", ipHdrLen, dataLen);

      dataLen = printUDPinfo ((udpHdr_t *)(q + 1));

      break;

    default:
      printf ("%s", "Protocol Not Supported Yet");

      // Print IP header length and numBytes of the options
      ipHdrLen = (q->ip_verHlen & 0b00001111) * 4;
      dataLen = 0;

      printf ("IPhdr=%02d (Options %d bytes)", ipHdrLen, dataLen);
      return;
    }

  printf (" AppData=%5u", dataLen);
}

/*-------------------------------------------------------------------------*/
/* Print the ICMP info.
   Recall that all multi-byte data is in Network-Byte-Ordering
   Returns length of the ICMP header in bytes

*/
unsigned
printICMPinfo (const icmpHdr_t *p)
{
  unsigned icmpHdrLen = sizeof (icmpHdr_t);
  uint16_t *id, *seqNum;

  switch (p->icmp_type)
    {
    case ICMP_ECHO_REPLY:
      // Verify code == 0,
      // if not print "Invalid Echo Reply Code: %3d" and break
      if (p->icmp_code != 0)
        {
          printf ("Invalid Echo Reply Code: %3d", p->icmp_code);
        }
      else
        {
          uint16_t id = (p->icmp_line2[0] << 8) + p->icmp_line2[1];
          uint8_t seq = (p->icmp_line2[2] << 8) + p->icmp_line2[3];
          printf ("Echo Reply   id(BE)=0x%04x, seq(BE)= %4d", id, seq);
        }
      break;

    case ICMP_ECHO_REQUEST:
      // Verify code == 0,
      // if not print "Invalid Echo Request Code: %3d" and break
      if (p->icmp_code != 0)
        {
          printf ("Invalid Echo Request Code: %3d", p->icmp_code);
        }
      else
        {
          uint16_t id = (p->icmp_line2[0] << 8) + p->icmp_line2[1];
          uint8_t seq = (p->icmp_line2[2] << 8) + p->icmp_line2[3];
          printf ("Echo Request id(BE)=0x%04x, seq(BE)= %4d", id, seq);
        }
      break;

    default:
      printf ("ICMP Type  %3d (code %3d) not yet supported.", p->icmp_type,
              p->icmp_code);
    }

  printf (" ICMPhdr=%4u", icmpHdrLen);
  return icmpHdrLen;
}

/* ***************************** */
/*          PROJECT 2            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
/* Print the TCP info.
   Recall that all multi-byte data is in Network-Byte-Ordering
   Prints specific TCP format

*/
unsigned
printTCPinfo (const tcpHdr_t *p)
{
  uint16_t length = (0b1111000000000000 & ntohs (p->tcp_hrc));
  length = (length >> 12) * 4;
  unsigned optlen = length - 20;

  unsigned datalen = 0;

  unsigned srcport = ntohs (p->tcp_srcport);
  unsigned destport = ntohs (p->tcp_destport);

  char *protocol = "tcp";

  // Source port name
  char srcbuf[24];
  memset (srcbuf, 0, sizeof (srcbuf));
  portToStrServ (srcport, srcbuf, sizeof (srcbuf), protocol);

  // Destination port name
  char destbuf[24];
  memset (destbuf, 0, sizeof (destbuf));
  portToStrServ (destport, destbuf, sizeof (destbuf), protocol);

  // Print formatted length(s) and ports
  printf (" TCPhdr=%d (Options %2d bytes)", length, optlen);
  printf (" Port %5u %s -> %5u %s ", srcport, srcbuf, destport, destbuf);

  // Create a string of the control flags to print
  uint8_t flags = (0b0000000000111111 & ntohs (p->tcp_hrc));

  bool ack
      = false; // use to check if acknowledgement number needs to be printed
  bool psh = false;

  // SYN flag
  if ((0b00000010 & flags) == 0b00000010)
    {
      printf ("[SYN ");
    }
  else
    {
      printf ("[    ");
    }

  // PSH flag
  if ((0b00001000 & flags) == 0b00001000)
    {
      printf ("PSH ");
      psh = true;
    }
  else
    {
      printf ("    ");
    }

  // ACK flag
  if ((0b00010000 & flags) == 0b00010000)
    {
      printf ("ACK ");
      ack = true;
    }
  else
    {
      printf ("    ");
    }

  // FIN flag
  if ((0b00000001 & flags) == 0b00000001)
    {
      printf ("FIN ");
    }
  else
    {
      printf ("    ");
    }

  // RST flag
  if ((0b00000100 & flags) == 0b00000100)
    {
      printf ("RST ]");
    }
  else
    {
      printf ("    ]");
    }

  // Print the Sequence number
  printf (" Seq=%10u", ntohl (p->tcp_seqnum));

  // Only print Acknowledgement number if flag is set
  if (ack)
    {
      printf (" Ack=%10u ", ntohl (p->tcp_acknum));
    }
  else
    {
      printf ("                ");
    }

  // Print receiving window
  printf ("Rwnd=%5hu", ntohs (p->tcp_window));

  datalen = cap_len - 54; // subtract all headers from total captured length
  if (datalen <= 20 && !psh)
    {
      datalen = 0;
    }
  return datalen;
}

/*-------------------------------------------------------------------------*/
/* Print the UDP info.
   Recall that all multi-byte data is in Network-Byte-Ordering
   Prints specific UDP format
   Returns length of UDP packet

*/

unsigned
printUDPinfo (const udpHdr_t *p)
{
  unsigned datalen = ntohs (p->udp_len);

  unsigned srcport = ntohs (p->udp_srcport);
  unsigned destport = ntohs (p->udp_destport);

  char *protocol = "udp";

  // Source port name
  char srcbuf[24];
  memset (srcbuf, 0, sizeof (srcbuf));
  portToStrServ (srcport, srcbuf, sizeof (srcbuf), protocol);

  // Destination port name
  char destbuf[24];
  memset (destbuf, 0, sizeof (destbuf));
  portToStrServ (destport, destbuf, sizeof (destbuf), protocol);

  // Print formatted info
  printf (" UDP %5u Bytes. Port %5u %s", datalen, srcport, srcbuf);
  printf (" -> %5u %s ", destport, destbuf);

  return datalen - 8;
}

/* ***************************** */
/*          PROJECT 3            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
/* After reading info from the input PCAP file, print the destination
   of the current packet's MAC address and if that address is one of
   yours.

   If the address is not yours, return and do not copy it to the output
   PCAP file. Otherwise, respond to incoming ARP or ICMP message:

   - Copy the request packet (header + Ethernet frame) followed by your
     reply packet (header + Ethernet frame) to the output file.
   - For ICMP, the starting IP id must be 1000(base 10), then incremented by
     1 for each datagram after.
   - The IP flags should indicate "Do Not Fragment"

*/
void
processRequestPacket (packetHdr_t *pktHdr, uint8_t ethFrame[])
{
  etherHdr_t *ethPtr = (etherHdr_t *) ethFrame ;
  
  // Print the MAC addr and whether it is mine or not
  char buff[64] ;
  memset(buff, 0, 64) ;

  printf("%s", macToStr(ethPtr->eth_dstMAC, buff, 64)) ;

  bool mine = myMAC( ethPtr->eth_dstMAC ) ;
  if (mine) // Ethernet frame is targeting my machine
  {
    printf("   is mine") ;

    // Check if packet is an ARP or Echo request
    uint16_t ethType = ntohs (ethPtr->eth_type);

    switch (ethType)
      {
      case PROTO_ARP:  // ARP message

        arpMsg_t *arpPtr = (arpMsg_t *)(ethPtr + 1);

        // Only write/respond to ARP request packets
        if (ntohs(arpPtr->arp_oper) == ARPREQUEST)
        {

          uint8_t *targetMac ;
          targetMac = malloc(sizeof(uint8_t) * 6) ;

          // Only write/respond to ARP requests targeting my machine
          if (myIP(arpPtr->arp_tpa, &targetMac))
          {

            // Writing original packet -------------------------------------
            // Write the original packet header to the output file
            if (fwrite (pktHdr, 1, sizeof (packetHdr_t), pcapOutput) < sizeof (packetHdr_t))
            {
              errorExit("\nFailed to write to output PCAP file.") ;
            }

            // Write the original Ethernet frame to the output file
            if (fwrite (ethFrame, 1, pktHdr->incl_len, pcapOutput) < pktHdr->incl_len)
            {
              errorExit("\nFailed to write to output PCAP file.") ;
            }

            // Writing response packet -------------------------------------
            // Add 30 microseconds to the packet header
            pktHdr->ts_usec += 30 ;


            // Change the source and destination of the Ethernet frame
            for (int i = 0; i < 6; i++)
            {
              ethPtr->eth_dstMAC[i] = ethPtr->eth_srcMAC[i] ;
              ethPtr->eth_srcMAC[i] = targetMac[i] ;
            }
        

            // Change the ARP fields for the response
            arpPtr->arp_oper = htons(2) ;       // change operation to reply

            for (int i = 0; i < 6; i++)         // change target mac addr to the past source mac addr
            {
              arpPtr->arp_tha[i] = arpPtr->arp_sha[i] ; 
            }

            IPv4addr temp = arpPtr->arp_tpa ;
            arpPtr->arp_tpa = arpPtr->arp_spa ; // change target ip addr to the past ip addr

            for (int i = 0; i < 6; i++)         // change source mac addr to my mac addr
            {
              arpPtr->arp_sha[i] = targetMac[i] ;
            }

            arpPtr->arp_spa = temp ;            // change source ip addr to my ip addr


            // Write the new packet header to the output file
            if (fwrite (pktHdr, 1, sizeof (packetHdr_t), pcapOutput) < sizeof (packetHdr_t))
            {
              errorExit("\nFailed to write to output PCAP file.") ;
            }

            // Write the new Ethernet frame to the output file
            if (fwrite (ethFrame, 1, pktHdr->incl_len, pcapOutput) < pktHdr->incl_len)
            {
              errorExit("\nFailed to write to output PCAP file.") ;
            }

          }
        }
        return;

      case PROTO_IPv4: // IP packet

        ipv4Hdr_t *ipPtr = (ipv4Hdr_t *)(ethPtr + 1);

        uint8_t *destMac;
        destMac = malloc(sizeof(uint8_t) * 6) ;

        // Only write/respond to IP headers targeting my machine
        if (myIP(ipPtr->ip_dstIP, &destMac))
        {

          // Only write/respond to ICMP Echo request packets
          if (ipPtr->ip_proto == PROTO_ICMP)
          {

            // Get the IP header length to make the ICMP struct pointer
            unsigned ipHdrLen = (ipPtr->ip_verHlen & 0b00001111) * 4 ;

            icmpHdr_t *icmpPtr = (icmpHdr_t *)(ipPtr + (ipHdrLen / 20)) ;

            if (icmpPtr->icmp_type == ICMP_ECHO_REQUEST && icmpPtr->icmp_code == 0)
            {

              // Writing original packet -------------------------------------
              // Write the original packet header to the output file
              if (fwrite (pktHdr, 1, sizeof (packetHdr_t), pcapOutput) < sizeof (packetHdr_t))
              {
                errorExit("\nFailed to write to output PCAP file.") ;
              }

              // Write the original Ethernet frame to the output file
              if (fwrite (ethFrame, 1, pktHdr->incl_len, pcapOutput) < pktHdr->incl_len)
              {
                errorExit("\nFailed to write to output PCAP file.") ;
              }

              // Writing response packet -------------------------------------
              // Add 30 microseconds to the packet header
              pktHdr->ts_usec += 30 ;


              // Change the source and destination of the Ethernet frame
              for (int i = 0; i < 6; i++)
              {
                ethPtr->eth_dstMAC[i] = ethPtr->eth_srcMAC[i] ;
                ethPtr->eth_srcMAC[i] = destMac[i] ;
              }


              // Change the IPv4 header fields
              ipPtr->ip_id = htons(identification) ;             // change id to 1000+
              identification++;

              ipPtr->ip_flagsFrag = htons(0b0100000000000000) ;  // change flag to "Do Not Fragment"

              IPv4addr temp   = ipPtr->ip_srcIP ;                // change the source and destination ip addrs
              ipPtr->ip_srcIP = ipPtr->ip_dstIP ;
              ipPtr->ip_dstIP = temp ;

              uint16_t checksum = 0;                             // calculate the new ip checksum 
              ipPtr->ip_hdrChk  = 0 ;
              checksum = inet_checksum(ipPtr, sizeof(ipv4Hdr_t)) ;
              ipPtr->ip_hdrChk = htons(checksum) ;


              // Change ICMP pointer fields
              icmpPtr->icmp_type = ICMP_ECHO_REPLY ;             // change the type to echo reply

              checksum = 0 ;                                     // calculate the new icmp checksum
              unsigned dataLen = ipPtr->ip_totLen - ipHdrLen ;
              
              icmpPtr->icmp_check = 0;
              checksum = inet_checksum(icmpPtr, sizeof(icmpHdr_t) + dataLen);
              icmpPtr->icmp_check = htons(checksum) ;


              // Write the new packet header to the output file
              if (fwrite (pktHdr, 1, sizeof (packetHdr_t), pcapOutput) < sizeof (packetHdr_t))
              {
                errorExit("\nFailed to write to output PCAP file.") ;
              }

              // Write the new Ethernet frame to the output file
              if (fwrite (ethFrame, 1, pktHdr->incl_len, pcapOutput) < pktHdr->incl_len)
              {
                errorExit("\nFailed to write to output PCAP file.") ;
              }

            }
          }
        }
        return;

      default:         // Unrecognized protocol (ignore) 
        return;
      }

  }
  else     // Ethernet frame is NOT targeting my machine 
  {
    printf("   is NOT mine") ;
  }
}

/*-------------------------------------------------------------------------*/
/* Open the PCAP file with fname and write its global header from pre-filled
   info in buffer p.

   Returns 0 on success, otherwise -1.

*/
int
writePCAPhdr (char *fname, pcap_hdr_t *p)
{
  // Open the output file
  pcapOutput = fopen (fname, "w+");

  // Write the global header into the output PCAP
  if (fwrite (p, 1, sizeof (pcap_hdr_t), pcapOutput) < sizeof (pcap_hdr_t))
    {
      return -1;
    }

  return 0;
}

/*-------------------------------------------------------------------------*/
/* Read IP-to-MAC mappings from file arpDB into the myARPmap[] global array.

   Returns the number of mappings read and sets mapSize to that number,
   otherwise returns -1.

*/
int
readARPmap (char *arpDB)
{
  // Open the ARP database file
  FILE *arpFile = fopen (arpDB, "r");

  char lineBuff[64];
  memset (lineBuff, 0, 32);

  // Parse each line of the file
  int numMappings = 0;

  while (fgets (lineBuff, 64, arpFile) != NULL)
    {
      // Declare an arpmap struct to put in the myARPmap array
      arpmap_t *map = (arpmap_t *)malloc (sizeof (arpmap_t));

      // Tokenize each line by the spaces
      char *ip = strtok (lineBuff, " "); // the IP address as a string
      char *mac = strtok (NULL, " ");    // The MAC address as a string

      // Iterate through the IP string and concat the bytes
      char *ipDigit = strtok (ip, ".");
      uint32_t ipAddr = (uint8_t)atoi (ipDigit);

      while (ipDigit != NULL)
        {
          uint8_t digit = (uint8_t)atoi (ipDigit);

          ipAddr = ipAddr << 8;
          ipAddr += digit;

          ipDigit = strtok (NULL, ".");
        }
      map->ip = ipAddr;

      // Iterate through the MAC string and concat the bytes
      char *macDigit = strtok (mac, ":");

      int i = 0;
      while (macDigit != NULL && i < ETHERNETHLEN)
        {
          uint8_t digit = (uint8_t)strtol (macDigit, NULL, 16);

          map->mac[i] = digit;

          macDigit = strtok (NULL, ":");
          i++;
        }

      myARPmap[numMappings] = *map;

      numMappings++;
    }

  mapSize = numMappings;

  return numMappings;
}

/*-------------------------------------------------------------------------*/
/* Computes the Internet Checksum using One-Complement Arithmetic on an
   array of 16-bit values in data with a total of lenBytes bytes.

   Returns the checksum as a 16-bit value

*/
uint16_t inet_checksum(void *data, uint16_t lenBytes) {
    uint8_t *data_ptr = (uint8_t*)data;
    uint32_t checksum = 0;

    // Check if number of bytes is even
    if (lenBytes % 2 != 0)
    {
      data_ptr[lenBytes] = 0 ;
      lenBytes++;
    }

    for (int i = 0; i < lenBytes; i += 2) {

      uint16_t word = data_ptr[i] ;
      word = (word << 8) + data_ptr[i+1];

      checksum += word ;
    }

    if (checksum > 0xffff)
    {
      checksum += checksum >> 16 ;
    }

    return (uint16_t) (~checksum);
}


/*-------------------------------------------------------------------------*/
/* Checks if someIP is one of yours.

   If not, and ptr != NULL, then set ptr to NULL.

   If it is, and ptr != NULL, then set ptr to point at the corresponding
   MAC address inside myARPmap[] global array.

   Return true if IP is yours, otherwise false.

*/
bool
myIP (IPv4addr someIP, uint8_t **ptr)
{ 
  for (int i = 0; i < mapSize; i++) {
    if (myARPmap[i].ip == ntohl(someIP.ip)){
      *ptr = myARPmap[i].mac ;
      return true;
    }
  }
  
  ptr = NULL;
  return false; 
}

/*-------------------------------------------------------------------------*/
/* Checks if someMAC is yours. Broadcast is yours as well.

   Returns true if it is yours, false otherwise.

*/
bool
myMAC (uint8_t someMAC[])
{   
  bool broadcast = false;

    for (int i = 0; i < mapSize; i++) {
        for (int j = 0; j < 6; j++) {

            if (someMAC[j] != myARPmap[i].mac[j]) {
                break;
            }

            if (j == 5) {
                if (someMAC[j] == myARPmap[i].mac[j]) {
                    return true;
                }
            } 
        }
    }

    for (int i = 0; i < 6; i++)
    {
      if (someMAC[i] == 0xff)
      {
        broadcast = true ;
      }
      else
      {
        broadcast = false ;
        break ;
      }
    }

  return broadcast ;
}

/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/

/* Convert IPv4 address 'ip' into a dotted-decimal string in 'ipBuf'.
   Returns 'ipBuf'  */

char *
ipToStr (const IPv4addr ip, char *ipBuf)
{
  if (!ipBuf)
    {
      return NULL;
    }
  snprintf (ipBuf, 64, "%d.%d.%d.%d", ip.byte[0], ip.byte[1], ip.byte[2],
            ip.byte[3]);
  return ipBuf;
}

/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx
    in the caller-provided 'buf' whose maximum 'size' is given
    Do not overflow this buffer
    Returns 'buf'  */

char *
macToStr (const uint8_t *p, char *buf, int size)
{
  if (!buf)
    {
      return NULL;
    }

  bool allZeros = true;
  int i = 0;
  while (allZeros && i < 6)
    {
      if (p[i] != 0)
        {
          allZeros = false;
        }

      i++;
    }

  // Adresses of all 0s are not valid addresses
  if (allZeros)
    {
      snprintf (buf, size, "ff:ff:ff:ff:ff:ff");
      return buf;
    }

  snprintf (buf, size, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3],
            p[4], p[5]);
  return buf;
}

/*-------------------------------------------------------------------------*/
/*  Convert a port number to the format (%7s) or (   *** ) if no service
    in the caller-provided 'buf' whose maximum 'size' is given
    Do not overflow this buffer
    Returns 'buf'  */

char *
portToStrServ (unsigned port, char *buf, int size, char *protocol)
{
  // Buf must be initialized
  // Protocol must be initialized and equal "tcp" or "udp"
  if (!buf || !protocol
      || (strcmp ("tcp", protocol) != 0 && strcmp ("udp", protocol) != 0))
    {
      return buf;
    }

  // Otherwise, return port server name using the servent struct
  struct servent *service = getservbyport (htons (port), protocol);

  // service == NULL if no known service name
  if (!service)
    {
      snprintf (buf, size, "(   *** )");
    }
  else
    {
      snprintf (buf, size, "(%7s)", service->s_name);
    }

  return buf;
}

/*-------------------------------------------------------------------------*/
/*  Print a list of myARPmap addresses */
void printMyARPmap()
{
  for (int i = 0; i < mapSize; i++)
  {
    // Print the index
    printf("\n%d:       ", i);

    // Print the current IP address
    for (int j = 3; j >= 0; j--)
    {
      uint8_t ip = myARPmap[i].ip >> (8 * j) ;
      if (j == 0)
      {
        printf("%d    ", ip);
      } 
      else
      {
      printf("%d.", ip) ;
      }
    }

    // Print the MAC address
    for (int j = 0; j < 6; j++)
    {
      if (j == 5)
      {
        printf("%02x", myARPmap[i].mac[j]);
      } 
      else
      {
      printf("%02x:", myARPmap[i].mac[j]) ;
      }
    }
  }
  printf("\n") ;
}

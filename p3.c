/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022

    Implemented By:     Zoe Zinn
    File Name:          p3.c

---------------------------------------------------------------------------*/

#include "mypcap.h"
#include "openssl/bio.h"

/*-------------------------------------------------------------------------*/
void
usage (char *cmd)
{
  printf ("Usage: %s fileName\n", cmd);
}

/*-------------------------------------------------------------------------*/

#define MAXBUF 10000 /* num Bytes in largest ethernet frame */

int
main (int argc, char *argv[])
{
  char       *pcapIn;
  char       *pcapOut;
  char       *arpMap;
  uint8_t     data[MAXBUF];
  pcap_hdr_t  pcapHdr;
  packetHdr_t pktHdr;
  uint8_t     ethFrame[MAXFRAMESZ];
  etherHdr_t *frameHdrPtr = (etherHdr_t *)ethFrame;

  // Validate arguments
  if (argc < 4)
    {
      usage (argv[0]);
      exit (EXIT_FAILURE);
    }
  pcapIn  = argv[1];
  pcapOut = argv[2];
  arpMap  = argv[3];


  // Read the global header of the pcapInput file
  memset (&pcapHdr, 0, sizeof (pcap_hdr_t));
  if (readPCAPhdr (pcapIn, &pcapHdr) == -1)
    {
      // Exit and close files if there is no PCAP file or cannot be read
      errorExit ("Failed to read global header from the PCAP file");
    }


  // Write global header from pcapIn to pcapOut
  if (writePCAPhdr (pcapOut, &pcapHdr) == -1)
    {
      errorExit ("Failed to open the PCAP output file and could not write "
                 "global header");
    }
  printf ("\nOutput PCAP file created and its global header set up\n");


  // Read arpMap file and put mappings in the myArpMap array
  if (readARPmap (arpMap) == -1)
    {
      errorExit ("Failed to read arpDB file");
    }


  // Print myARPmap array
  printf("\nHere is the listing of my ARP mapping database") ;
  printMyARPmap() ;


    // Set all bytes to 0:
    memset(&pktHdr, 0, sizeof(packetHdr_t));
    memset(ethFrame, 0, MAXFRAMESZ);

    printf("\n Frame #     Its Destination MAC\n");    
    

    // Read one packet at a time
    int i = 1;
    while (getNextPacket(&pktHdr, ethFrame))
    {
      // Print packet number
      printf("%6d )     ", i);

      // Get data in the ethernet header
      frameHdrPtr = (etherHdr_t  *) ethFrame;

      // Call processRequestPacket() to determine if the packet's destinations
      // is one of my addresses
      processRequestPacket(&pktHdr, ethFrame) ;

      puts("") ;

      // Reset values for next iteration
      memset(&pktHdr, 0, sizeof(packetHdr_t));
      memset(ethFrame, 0, MAXFRAMESZ);

      i++;
    }

    // Clean-up
    printf("\nReached end of PCAP file '%s' processed %5d packets\n" , pcapIn, (i - 1) ) ;

    cleanUp ();
}

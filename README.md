To run this program, enter the "make all" command of the makefile in the terminal then run the p3.c file with the ./p3 command as such: 

    make all
    ./p3 <input pcap file> <output pcap file> <target address list file>

Where the input and output pcap file names must have the ".pcap" extenstion and the target address list file must have the IP address and MAC pair separated by spaces and delimited by each line, following the layout of the arp.dat example file. 

An example run with the provided files:

    make all
    ./p3 test_files/test1_input.pcap test_files/output.pcap test_files/arp.dat

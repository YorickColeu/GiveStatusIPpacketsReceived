# GiveStatusIPpacketsReceived
This software read a pcap file and give a status per time slot on how much was the packets length received by IP source

# Prerequise

Before to compile this program, you need to install the libpcap library

# Compile this project
`gcc -Wall ./src/main.c ./src/functions.c -o GiveStatusIPpacketsReceived -lpcap`

# Execute this program
Give the absolute path of a pcap file as an argument to the program.

Example:

`./GiveStatusIPpacketsReceived /home/usrname/mycap.pcap`

You can use the file given as an example

# Limitation

* A maximun value of 100000 different IP packets can be computed by the program, otherwise the program will lead to a segmentation fault
* Only IPv4 packets are taken in account

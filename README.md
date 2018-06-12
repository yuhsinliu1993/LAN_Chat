# Chat in LAN

Implement a simple chat program in LAN using Linux **[packet(7)](http://man7.org/linux/man-pages/man7/packet.7.html)** socket. Instead of sending IP packets, you have to broadcast chat messages using layer 2 broadcast packets.

You have to indicate the `DEFAULT_IF` you want to use in the source code `DEFINE` section.

The `DEFAULT_IF` is `enp0s8`

## Requirements
- [x]  Enumerate all Ethernet compatible network interfaces.
- [x]  Ask the user to provide his/her username.
- [x]  Repeatedly ask the user to enter his/her message. The message is then broadcasted to all enumerated Ethernet-compatible network interfaces.
- [x]  At the same time, your program should receive messages broadcasted by other host in connected LANs.


## Sample Outputs

```
$ sudo ./main
Enumerated network interfaces:
2 - enp0s3     010.000.002.015 0xffffff00 (010.000.002.255) 08:00:27:98:ca:e5
3 - enp0s8     010.000.001.001 0xffffff00 (010.000.001.255) 08:00:27:6a:11:25
Enter your name: aaaaa
Welcome, 'aaaaa'!
>>> <08:00:27:5b:d1:4c> [bbbbb]: hello, everybody here?
hello!
>>> <08:00:27:5b:d1:4c> [bbbbb]: this is bbbbb

>>>
```

If you look at the packet dumped by **[tcpdump](http://man7.org/linux/man-pages/man1/tcpdump.1.html)**, here is the sample output for the previous running example.

```
$ sudo tcpdump -XXni enp0s8 broadcast
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s8, link-type EN10MB (Ethernet), capture size 262144 bytes
22:11:44.248768 08:00:27:5b:d1:4c > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x0801), length 60:
        0x0000:  ffff ffff ffff 0800 275b d14c 0801 5b62  ........'[.L..[b
        0x0010:  6262 6262 5d3a 2068 656c 6c6f 2c20 6576  bbbb]:.hello,.ev
        0x0020:  6572 7962 6f64 7920 6865 7265 3f00 0000  erybody.here?...
        0x0030:  0000 0000 0000 0000 0000 0000            ............
22:11:46.488895 08:00:27:5b:d1:4c > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x0801), length 60:
        0x0000:  ffff ffff ffff 0800 275b d14c 0801 5b62  ........'[.L..[b
        0x0010:  6262 6262 5d3a 2074 6869 7320 6973 2062  bbbb]:.this.is.b
        0x0020:  6262 6262 0000 0000 0000 0000 0000 0000  bbbb............
        0x0030:  0000 0000 0000 0000 0000 0000            ............
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel
```

## Hints
1. To enumerate all available interfaces in your host, you can work with the **[getifaddrs(3)](http://man7.org/linux/man-pages/man3/getifaddrs.3.html)** function. This function returns a pointer to a linked-list of interface addresses, which includes H/W address and network layer addresses. The type of addresses can be determined by the family of the sockaddr data structure.
2. For sending and receiving packets, please read **[packet(7)](http://man7.org/linux/man-pages/man7/packet.7.html)** CAREFULLY.
3. When creating a packet socket, you may want to work with SOCK_RAW type to manage Layer 2 (Ethernet) header by yourself.
4. You will have to specify the "ethernet type" for your Layer 3 packet. Simply choose one number that has not been registered by other protocols. In our running example, we use the number 0x0801 (ETH_P_IP + 1).
5. The broadcast address in Ethernet is FF:FF:FF:FF:FF:FF (in hexadecimal).
6. When sending a message, you may simply put your message as a payload of the Ethernet protocol.

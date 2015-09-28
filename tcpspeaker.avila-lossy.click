// Dan Levin
// 2009/08/20 tcpspeaker.2hosts-avila.click
//
//
//                ---------------------------
//    TCP SRC --> | $DEV0 tcps0 tcps1 $DEV1 | <-- TCP DST 
//                ---------------------------
//
// conduct a tcp session between ips on $DEV0 and $DEV1
// 
// IMPORTANT: 	Ensure that iptables are all flushed and all ALLOW policy! Ensure
//				
// USAGE: 		click <thisconfig> dev0 <src-side interface name> dev1=<dst-side interface name> dstip=<destination ip> srcip=<the ip of the outbound interface>

ChatterSocket(TCP, 5001);
ControlSocket(TCP, 5002);

out0 :: Queue -> ToDevice($DEV0)
in0  :: FromDevice($DEV0, SNIFFER false) -> c0 :: Classifier(12/0806 20/0001,
												 12/0806 20/0002,
												 12/0800 23/06,
												 -);
out1 :: Queue -> ToDevice($DEV1)
in1  :: FromDevice($DEV1, SNIFFER false) -> c1 :: Classifier(12/0806 20/0001,
												 12/0806 20/0002,
												 12/0800 23/06,
												 -);


todump :: ToDump(/root/tcpsdumpfile.pcap, ENCAP IP)

drop0:: RandomSample(DROP $DROP)

tcps0 :: TCPSpeaker(FIN_AFTER_TCP_FIN 1, MAXSEG 1450, RCVBUF $RBUF0, WINDOW_SCALING $WS0, FIN_AFTER_UDP_IDLE 0, IDLETIME 20, VERBOSITY $VERB0);
tcps1 :: TCPSpeaker(FIN_AFTER_TCP_FIN 1, MAXSEG 1450, RCVBUF 0x10000, WINDOW_SCALING 0, FIN_AFTER_UDP_IDLE 0, IDLETIME 20, VERBOSITY $VERB1);

aq0 :: ARPQuerier($DEV0)
aq1 :: ARPQuerier($DEV1)

///////////////////////////
// From DEV0 to DEV1
//////////////////////////

// ARP Requests
c0[0] 
	-> ARPResponder($DEV0)
	-> out0 

// ARP Replies
c0[1]
	-> [1]aq0

// TCP
c0[2]
	-> Strip(14)
	-> CheckIPHeader
	-> drop0
	-> IPPrint()
	-> t1 :: Tee[1]
	-> [0]tcps0

// Other Not TCP packets are dropped
c0[3]
    -> Discard;

drop0[1]
	-> IPPrint(DROP)
	-> Discard

tcps0[0]
	-> [1]tcps1

tcps1[1]
	-> GetIPAddress(16)
	-> SetTCPChecksum
	-> SetIPChecksum
	-> aq1
	-> out1 

///////////////////////////
// From DEV1 to DEV0
//////////////////////////

// ARP Requests
c1[0] 
	-> ARPResponder($DEV1)
	-> out0 

// ARP Replies
c1[1]
	-> [1]aq1

// TCP
c1[2]
	-> Strip(14)
	-> CheckIPHeader
	-> [0]tcps1

// Other Not TCP packets are dropped
c1[3]
    -> Discard;

tcps1[0]
	-> [1]tcps0

tcps0[1]
	-> GetIPAddress(16)
	-> SetTCPChecksum
	-> SetIPChecksum
	-> t2 :: Tee[1]
	-> aq0
	-> out0 



t1[0]
	-> todump

t2[0]
	-> todump

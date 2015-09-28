// Dan Levin
// 2009/08/20 tcpspeaker.2hosts-avila.click
//
//
//                ---------------------------
//    TCP SRC --> | $DEV0 			  $DEV1 | <-- TCP DST 
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


aq0 :: ARPQuerier($DEV0)
aq1 :: ARPQuerier($DEV1)

///////////////////////////
// From DEV0 to DEV1
//////////////////////////

// ARP Requests
c0[0] 
	-> ARPResponder($DEV0, 10.0.116.0/24 $DEV0, 10.0.113.0/24 $DEV0)
	-> out0 

// ARP Replies
c0[1]
	-> [1]aq0

// TCP
c0[2]
	-> Strip(14)
	-> CheckIPHeader
	-> GetIPAddress(16)
	-> SetTCPChecksum
	-> SetIPChecksum
	-> aq1
	-> out1 

// Other Not TCP packets are dropped
c0[3]
    -> Discard;

///////////////////////////
// From DEV1 to DEV0
//////////////////////////

// ARP Requests
c1[0] 
	-> ARPResponder($DEV1, 10.0.114.0/24 $DEV1, 10.0.111.0/24 $DEV1)
	-> out1 

// ARP Replies
c1[1]
	-> [1]aq1

// TCP
c1[2]
	-> Strip(14)
	-> CheckIPHeader
	-> GetIPAddress(16)
	-> SetTCPChecksum
	-> SetIPChecksum
	-> aq0
	-> out0

// Other Not TCP packets are dropped
c1[3]
    -> Discard;

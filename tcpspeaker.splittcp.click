// Dan Levin
// 2009/08/20 demo.tcpspeaker.click
//
//
//              -------------------------------
// TCP Host --> eth0  tcps0   <->   tcps1  eth1 <- TCP Host
//              -------------------------------
//

ChatterSocket(TCP, 5010);
ControlSocket(TCP, 5011);

tun0  :: KernelTun(10.2.0.1/24, DEVNAME tun0) 
tun1  :: KernelTun(10.2.1.1/24, DEVNAME tun1) 

tcps0 :: TCPSpeaker(FIN_AFTER_TCP_FIN 1, MAXSEG 1450, RCVBUF 0x100000, WINDOW_SCALING 3, FIN_AFTER_UDP_IDLE 0, IDLETIME 20, VERBOSITY $VERB0);
tcps1 :: TCPSpeaker(FIN_AFTER_TCP_FIN 1, MAXSEG 1450, RCVBUF 0x100000, WINDOW_SCALING 3, FIN_AFTER_UDP_IDLE 0, IDLETIME 20, VERBOSITY $VERB1);

///////////////////////////
//tcps0 (simulating edge node a)
//////////////////////////

tun0
	-> CheckIPHeader
//	-> IPPrint([0]tcps0)
	-> StoreIPAddress(10.2.1.2, src)
	-> StoreIPAddress(10.2.1.1, dst)
	-> GetIPAddress(16)
	-> [0]tcps0

tcps0[0]
	-> [1]tcps1

tcps0[1]
	-> StoreIPAddress(10.2.0.2, src)
	-> StoreIPAddress(10.2.0.1, dst)
	-> GetIPAddress(16)
//	-> IPPrint(tcps0[1])
	-> SetTCPChecksum
	-> SetIPChecksum
	-> tun0


///////////////////////////
//tcps1 (simulating edge node b)
//////////////////////////

tun1
	-> CheckIPHeader
//	-> IPPrint([0]tcps1)
	-> [0]tcps1

tcps1[0]
	-> [1]tcps0

tcps1[1]
//	-> IPPrint(tcps1[1])
	-> SetTCPChecksum
	-> SetIPChecksum
	-> tun1

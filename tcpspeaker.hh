/*
 * Copyright (c) 1993, 1986, 1988, 1993, 1994
 * The Regents of the University of California. 
 * Copyright (c) 1994-2002
 * Gary R. Wright & W. Richard Stevens, Addison Wesley
 * Copyright (c) 2008
 * Harald Schioeberg, Technische Universitaet Berlin
 *
 * All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 * 
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. All advertising materials mentioning features or use of this
 *     software must display the following acknowledgement: This product
 *     includes software developed by the University of California,
 *     Berkeley and its contributors.
 *  4. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS
 *  IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 *  FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 *  SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 *  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 *  OF SUCH DAMAGE.
 * 
 *  Note: This code was published with 4.4BSD-Lite. 
 *  It was annotated by Wright/Stevens in TCP/IP Illustrated Vol.2.
 *  It was adopted for use in the Click Modular Router by Harald Schioeberg.
 */

/*
=c
TCPSpeaker(KEYWORDS)

=s tcp

implements tcp state, retransmission, congestion control

=d 

Has a full tcp connection on in/out port 0 (statefull side).
Takes and sends "stateless" tcp packets on in/out port 1. 

The stateless packets contain valid minimal TCP/IP headers. Most of the
fields are ignored. Use other elements to get rid of these headers. 
The statefull side can be connected to any other TCP speaking entity.

This element does not perform checksumming on either side. 

*/

#ifndef CLICK_TCPSPEAKER_HH
#define CLICK_TCPSPEAKER_HH

#include <click/element.hh>
#include <click/multiflowdispatcher.hh>
#include <click/error.hh>
#include <click/notifier.hh>
#include <click/straccum.hh>
#include <click/hashtable.hh>
// #include "netinet/tcp.h"
#include <clicknet/tcp.h>
#define TCPOUTFLAGS
#define TCPSTATES
#include "tcp_fsm.h"
// #define TCPTIMERS
#include "tcp_timer.h"
#include "tcp_var.h"

#define INCOMING 1
#define OUTGOING 2

// TCPSpeaker Specific Verbosity Bitmask definitions
#define VERB_TCP 	0x10000  // anything tcp input or output related
#define VERB_STATES 	0x20000  // for state changes
#define VERB_TIMERS 	0x40000  // for timer events
#define VERB_TCPQUEUE 	0x80000  //  for the TCP Recv Queue
#define VERB_TCPFIFO 	0x100000 // for the TCP Send FIFO 
#define VERB_TCPSTATS   0x200000 // for the TCP Send FIFO 

#define MAX_TCPOPTLEN 40

#define TCP_REXMTVAL(tp) \
	(((tp)->t_srtt >> TCP_RTT_SHIFT) + (tp)->t_rttvar)


#define rot(x,k) (((x)<<(k)) ^ ((x)>>(32-(k))))
#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}

#define portswap(x) ( ((uint32_t)(x) << 16) | ((uint32_t)(x) >> 16
/* #define setports(d,p) (memcpy(&(d), &(p), 4)) */


#define TCPS_STATEFULL_INPUT 0
#define TCPS_STATELESS_INPUT 1
#define TCPS_STATEFULL_OUTPUT 1
#define TCPS_STATELESS_OUTPUT 0
CLICK_DECLS

struct ConnectionId { 
	uint32_t _saddr; 
	uint32_t _daddr; 
	uint32_t _ports; 

	ConnectionId() : _saddr(0), _daddr(0), _ports(0){}
	ConnectionId(uint32_t s, uint32_t d, uint32_t p)
	{ 
		_saddr = s;
		_daddr = d;
		_ports = p;
	}

	inline size_t hashcode() const
	{
		uint32_t a = _saddr;
		uint32_t b = _daddr;
		uint32_t c = _ports; 
		final(a,b,c);
		return c;
	}

	bool operator== (const ConnectionId &a) const
	{
		return (_saddr == a._saddr && _daddr == a._daddr && _ports == a._ports); 
	}
};


class TCPConnection; 

// Queue of incoming segments to be reassembled and passed to stateless output
class TCPQueue { 

    class TCPQueueElt { 
		public: 
		TCPQueueElt(WritablePacket *p, tcp_seq_t s, tcp_seq_t n) { 
			_p = p; 
			seq = s; 
			seq_nxt = n; 
			nxt = NULL;
		}

		~TCPQueueElt() {}; 
		WritablePacket 	*_p;
		TCPQueueElt 	*nxt; 
		tcp_seq_t		seq; 
		tcp_seq_t		seq_nxt; 
	};

    public: 
    TCPQueue(TCPConnection *con);
    ~TCPQueue(); 

	int push(WritablePacket *p, tcp_seq_t seq, tcp_seq_t seq_nxt);
	void loop_last();
	WritablePacket *pull_front();

	// @Harald: Aren't all of these seq num arithmetic operations unsafe from
	// wraparound ?
	tcp_seq_t first() { return _q_first ? _q_first->seq : 0; }
	tcp_seq_t first_len() { return _q_first ? (_q_first->seq_nxt - _q_first->seq) : 0; }
	tcp_seq_t expected() { return _q_tail ? _q_tail->seq_nxt : 0; }
	tcp_seq_t tailseq() { return _q_tail ? _q_tail->seq : 0; }
	tcp_seq_t last()  { return _q_last ? _q_last->seq : 0; } 
	tcp_seq_t last_nxt()  { return _q_last ? _q_last->seq_nxt : 0; } 
	tcp_seq_t bytes_ok() { return _q_last ? _q_last->seq - _q_first->seq : 0; } 
	bool is_empty() { return _q_first ? false : true; }
	//FIXME: Returns true even if there is a hole at the front! Decide whether
	//to rethink what we mean by "ordered"
	bool is_ordered() { return (_q_last == _q_tail); }

    StringAccum * pretty_print(StringAccum &sa, int width); 

    private: 
	int verbosity() const;
    TCPConnection *_con;   /* The TCPConnection to which I belong */

    TCPQueueElt *_q_first; /* The first segment in the queue 
							 (a.k.a. the head element) */
    TCPQueueElt *_q_last;  /* The last segment of ordered data 
							 in the queue (a.k.a. the last 
							 segment before a gap occurs)  */
    TCPQueueElt *_q_tail;   /* The very last segment in the queue 
							 (a.k.a. the next expected in-order 
							 ariving segment should be inserted
							 after this segment )  */
};

// The Queue of segments ready to packetize and send via pull
class TCPFifo 
{ 
	public:
#define FIFO_SIZE 256
    TCPFifo(TCPConnection *con);
    ~TCPFifo(); 
    int 	push(WritablePacket *);
    int 	pkt_length() { return (_head - _tail) % FIFO_SIZE; }
    bool 	is_empty() { return ( 0 == pkt_length()) ; }
    int 	pkts_to_send(int offset, int win); 
    void 	drop_until (tcp_seq_t offset); 

    tcp_seq_t byte_length() { return _bytes; } 
    WritablePacket *pull(); 
    WritablePacket *get (tcp_seq_t offset); 

	protected:
    WritablePacket **_q; 
    int 	_head; 
    int 	_tail; 
    int 	_peek_cache_position; 
    int 	_peek_cache_offset; 
    tcp_seq_t _bytes;

	private:
    TCPConnection *_con;   /* The TCPConnection to which I belong */
	int verbosity() const;
};

struct tcp_globals 
{ 
		int 	tcp_keepidle; 
		int 	tcp_keepintvl; 
		int 	tcp_maxidle; 
		int		tcp_mssdflt; 
		int		tcp_rttdflt; 
		int		so_flags;
		int 	so_idletime; 
		int 	window_scale; 
		bool	use_timestamp; 
		uint32_t tcp_now;
		tcp_seq_t so_recv_buffer_size; 
};

class TCPSpeaker; 


class TCPConnection : public MultiFlowHandler 
{
    public: 
	TCPConnection(TCPSpeaker *, const IPFlowID &id, const char dir); 
	~TCPConnection() {
	    debug_output(VERB_MFD_QUEUES, 
	    "***** DELETING TCPConnection at <%x> ***** \n",
	    this); }; 
	
	void 	tcp_input(WritablePacket *p);
	void    push(const int port, Packet *p); 
	Packet 	*pull(const int port); 

	void 	tcp_output();
	int		usrsend(WritablePacket *p); 
	void    usrclosed() ; 
	void 	usropen(); 

#define SO_STATE_HASDATA	0x01
#define SO_STATE_ISCHOKED   0x10

	short state() const { return tp->t_state; } 
	TCPSpeaker* speaker() const; 
	bool has_pullable_data() { return !_q_recv.is_empty() && SEQ_LT(_q_recv.first(), tp->rcv_nxt); } 
	void print_state(StringAccum &sa); 
	int verbosity() const;
	

    protected: 
	friend class TCPSpeaker; 

	class SpeakerQueueElem { 
		public:
		TCPConnection *next; 
		TCPConnection *prev; 
		int qid; 
	} _speaker_queue; 

	SpeakerQueueElem * speaker_queue_elt() { return &_speaker_queue; } 
	int	speaker_queue_id() { return _speaker_queue.qid; }

    void 		fasttimo();
	void 		slowtimo();
	void		tcp_timers(int timer); 
	int 		stateless_decap(WritablePacket*); 
	int 		stateless_encap(WritablePacket*); 
	//TODO give TCPQueue a ref to its connection.
    private: 
	ErrorHandler	*_errh; 
	tcpcb 		*tp;
	TCPFifo		_q_usr_input;
	TCPQueue	_q_recv; 
	tcp_seq_t	so_recv_buffer_size; 

	int			_so_state; 
	void 		_tcp_dooptions(u_char *cp, int cnt, const click_tcp *ti, 
					int *ts_present, u_long *ts_val, u_long *ts_ecr);
	void 		tcp_respond(tcp_seq_t ack, tcp_seq_t seq, int flags);
	void		tcp_setpersist(); 
	void		tcp_drop(int err); 
	void		tcp_xmit_timer(short rtt); 
	void 		tcp_canceltimers(); 
	u_int		tcp_mss(u_int); 
	tcpcb*		tcp_newtcpcb(); 
	tcp_seq_t	so_recv_buffer_space(); 
	void 		_do_iphdr(WritablePacket *p);
	void 		ip_output(WritablePacket *p); 
	inline void tcp_set_state(short);
	inline void print_tcpstats(WritablePacket *p, char *label);
	short tcp_state() const { return tp->t_state; } 

	Task		* _stateless_pull; 
	static bool	pull_stateless_input(Task *, void *); 
	MFHState        set_state(const MFHState new_state, const int port = -1); 

	void can_pull(const MultiFlowDispatcher * const neighbor, bool pullable ) {
	        if ( pullable
		    && dispatcher()->_output_port_neighbors[TCPS_STATELESS_OUTPUT] == neighbor 
		    && (! _stateless_pull->scheduled())  
		    && handler_state() == ACTIVE) { 
			_stateless_pull->reschedule(); 
		} 
	}; 
};


class TCPSpeaker : public MultiFlowDispatcher {
    public:
	TCPSpeaker() { _ip_id = 0; };
	~TCPSpeaker() { /*TODO delete all sub-datastructures, although this should never happen */ }; 

	const char *class_name() const { return "TCPSpeaker"; }
	const char *port_count() const { return "2/2"; }
	const char *processing() const { return "ha/lh"; } 
	const char *mfh_processing() const { return "ha/lh"; } 
	// Flow code xy/xy means packets travel only from port 0 to 0 and from 1 to 1
	const char *flow_code()  const { return "xy/xy"; } 

	MultiFlowHandler * new_handler(const IPFlowID & flowid, const int direction) { 
		return new TCPConnection(this, flowid, direction);
	}

	bool is_syn(const Packet * packet); 

	uint16_t get_and_increment_ip_id() { return htons(++_ip_id); }
	int 	configure(Vector<String> &conf, ErrorHandler * errh); 
	void 	*cast (const char *n); 
	int 	initialize(ErrorHandler * errh);

	int llrpc(unsigned, void *);
	void add_handlers();
	ErrorHandler *error_handler()	{ return _errh; }

	// following method was declared const, but g++ ignores this
	int verbosity() 			{ return _verbosity; }
	tcp_globals *globals() 	{ return &_tcp_globals; } 
	uint32_t tcp_now() 		{ return _tcp_globals.tcp_now; }
	/*	const tcpcb * tp() {return _tp;} */
  	//	static void     _tcp_timer_close( Timer *, void  *);  
  	//	static void     _tcp_timer_wait( Timer *, void  *);  


	/* MultiFlowHandler * create_handler(MultiFlowHandler * const, const Packet * const ); */ 

    protected:
	friend class	TCPConnection; 
	tcpstat 		_tcpstat; 

    private: 
	// Element Handler Methods
	static String read_verb(Element*, void*);
	static int write_verb(const String&, Element*, void*, ErrorHandler*);
	static String read_num_connections(Element*, void*);

	TCPSpeaker 		*_speaker;
	ErrorHandler	*_errh; 
// I believe the following two don't need to be in TCPSpeaker as they are
// TCPConnection-related. remove after confirming TCPSpeaker still works
// properly. (inserted on 2009.11.18)
//	TCPFifo 		_q_usr_input;
//	TCPQueue		_q_recv; 
	Timer			*_fast_ticks;
	Timer			*_slow_ticks;

	int 		_verbosity;
	uint16_t 	_ip_id; // incrementally increase IP hdr id across all flows
	void		run_timer(Timer *); 
	int 		iter_connections(void *, int);
	tcp_globals	_tcp_globals; 
};


inline TCPSpeaker *
TCPConnection::speaker() const { return dynamic_cast<TCPSpeaker*>(mfd()); } 

inline int
TCPConnection::verbosity() const { return speaker()->verbosity(); }

inline int
TCPQueue::verbosity() const { return _con->speaker()->verbosity(); }

inline int
TCPFifo::verbosity() const { return _con->speaker()->verbosity(); }

/* THE method where we register, and handle any TCP State Updates */
inline void 
TCPConnection::tcp_set_state(short state) {
	    short old = tp->t_state; 
	    StringAccum sa;
	    sa << *(flowid()); 
	    tp->t_state = state; 
		debug_output(VERB_STATES, "[%s] Flow: [%s]: State: [%s]->[%s]", speaker()->name().c_str(), sa.c_str(), tcpstates[old], tcpstates[tp->t_state]); 

		/* Set stateless flags which will dispatch the appropriately flagged
		 * signal packets into the mesh when we enter into one of these
		 * following states
		 */

		 /* stateless flags are disabled for now untill a better
		  * way of handling those is found */

		switch (state) {
			case TCPS_ESTABLISHED:
				set_state(ACTIVE);
				debug_output(VERB_STATES, "[%s] Flow: [%s]: Setting stateless SYN: [%d]", speaker()->name().c_str(), sa.c_str(), tp->t_sl_flags);
				break;
	//		case TCPS_CLOSE_WAIT:
			case TCPS_FIN_WAIT_1: 
			case TCPS_LAST_ACK:
				// tp->t_sl_flags = TH_FIN;
				/* 
				for (int port = 0; port <= 2; port++) 
				if ( ( output_port_dispatch(port) & MFD_DISPATCH_SCHEDULER) == MFD_DISPATCH_MFD_DIRECT ) { 
				    static_cast<MultiFlowHandler *>(output(port))->shutdown(output(port).remote_port()); 
				} 
				*/
				set_state(SHUTDOWN); 
				debug_output(VERB_STATES, "[%s] Flow: [%s]: Setting stateless FIN: [%d]", speaker()->name().c_str(), sa.c_str(), tp->t_sl_flags);
				break;
			case TCPS_CLOSED:
				set_state(CLOSE); 
				// tp->t_sl_flags = TH_RST;
				debug_output(VERB_STATES, "[%s] Flow: [%s]: Setting stateless RST: [%d]", speaker()->name().c_str(), sa.c_str(), tp->t_sl_flags);
				break;
		}
	};

CLICK_ENDDECLS
#endif

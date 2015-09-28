// -*- related-file-name: "../../lib/multiflowdispatcher.cc" -*-
#ifndef CLICK_MULTIFLOWDISPATCHER_HH
#define CLICK_MULTIFLOWDISPATCHER_HH

// used for debug_output
#ifdef CLICK_USERLEVEL
# include <stdarg.h>
#endif

#include <click/config.h>
#include <click/packet.hh>
#include <click/element.hh>
#include <click/notifier.hh>
#include <click/ipflowid.hh>
#include <click/hashtable.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>

#include <clicknet/ip.h>
#include <clicknet/udp.h>

#define QID_PULLABLE_BASE 	0
#define QID_PULLABLE0     	0
#define QID_PULLABLE1   	1
#define NUM_PULL_QUEUES		2
#define QID_DELETE      	2

// Check our verbosity bitmask against the supplied bitmask and if true
// produce the according chatter output
#define debug_output(mask, format, args...) \
		if ((mask) & (verbosity()))  \
	    click_chatter((format) ,## args);
#define SPKRNAME speaker()->name().c_str()

// Verbosity Bitmask definitions
#define VERB_NONE 		0
#define VERB_ALL  		0xffffffff
#define VERB_ERRORS 	0x01
#define VERB_WARNINGS 	0x02
#define VERB_INFO		0x04
#define VERB_DEBUG		0x08
#define VERB_MFD_QUEUES 0x10 // for the MFD Handler Queues
#define VERB_PACKETS 	0x20 // triggered on packet handling/traversal events
#define VERB_DISPATCH   0x40 // for anything related to interconnecting handlers
#define VERB_MFH_STATE  0x80 // for the 5-state statemachine of MFH
// TCPSPeaker specific bitmasks begin at 0x10000

/*TODO (dan) add a definition for QID_MIGRATE but I have to check everywhere
 * NUM_QUEUES is utilized to see that adding a new queue for migrations doesn't
 * break anything
 *#define QID_MIGRATE 		3
 *#define NUM_QUEUES 		4
 */

#define NUM_QUEUES      	3

#define Q_FLAG_NONE      0  
#define Q_FLAG_PULLABLE (1 << QID_PULLABLE)
#define Q_FLAG_DELETE   (1 << QID_DELETE)

#define DIR_INBOUND  0 
#define DIR_OUTBOUND 1

CLICK_DECLS

class MultiFlowDispatcher;


enum MFHState { CREATE, INITIALIZE, ACTIVE, SHUTDOWN, CLOSE }; 
class MultiFlowHandler { 
    public: 
    /** @brief Constructor, do not use default constructor 
    * @param mfd The MultiFlowDispatcher that the handler is associated * with
    * @param flowid The IPFlowID that identifies the packet
    * @param direction If not 0 then the flowid is inverted
    * 
    * Creates a flow handler. This constructor should always be called
    * even if it is overwirtten */
	MultiFlowHandler(
		MultiFlowDispatcher * mfd, 
		const IPFlowID & flowid, 
		const int direction );  

/*	virtual void initialize(const int port); 
	virtual void shutdown  (const int port);  */ 

    /** @brief analog to Element::push
    * @param port port from which the packet comes
    * @param p the packet
    * 
    * The default push kills all packets, this function should 
    * be overwritten if the Dispatcher has at least one push port
    *
    * @sa Element::push */
    virtual void push(const int port, Packet *p) = 0 ;

    /** @brief analog to Element::pull
    * @param port The port that is pulled
    * @return The packet
    * 
    * The default return always NULL. 
    * Note: There is no empty notifier. Use set_pullable instead.
    *
    * @sa Element::push set_pullable */
    virtual Packet *pull(const int port) = 0;

    /** @brief returns the IPFlowID of the Handler
    * 
    * @return the flowid */
	// following method was declared const, but g++ ignores this
    IPFlowID * flowid() { return &_flowid; }


    /** @brief returns the Dispatcher that the Handler is associated with
    * 
    * @return The MultiFlowDispatcher */
	// following method was declared const, but g++ ignores this
    MultiFlowDispatcher * mfd() const { return _mfd; }

    virtual ~MultiFlowHandler();  

	// Next 3 lines formerly declared protected
	void set_q_membership(int qid) 	{ /* click_chatter("q_mem %d", q_membership); */ q_membership |= (1 << qid); } 
    void del_q_membership(int qid) 	{ q_membership &= ~(1 <<qid); }
    bool is_q_member(int qid) 		{ 
		bool ismember = (q_membership >> qid) & 1;
//		click_chatter("DEBUG [%x] mfh::is_q_member: member of queue [%d]? [%s] q_mem: [%d]", this, qid, (ismember?"true":"false"), q_membership); 
		return ismember; 
	} 

    protected:
	// Next 2 lines formerly declared private
    MultiFlowHandler *next[NUM_QUEUES];
    MultiFlowHandler *prev[NUM_QUEUES]; 
   
    /** @brief set the Handler as pullable
    * @param port The port which is affected
    * @param pullable true means port is pullable, false means port is not pullable
    * 
    * This function manipulates the queues of the dispatcher and the
    * EMPTY_NOTIFIER. Do not manipulate either of them directly.
    * 
    * @sa push */
    void set_pullable(int port, bool pullable); 

    /** @brief this function is called if an input becomes pullable or
     * non-pullable. 
     * @param neighbor: the neighbor, that just changed its mind
     & @param pullable: indicates the new state
     * 
     * This function should be implemented by all MFH that have pull inputs
     */
    virtual void can_pull(const MultiFlowDispatcher * const neighbor , bool pullable ) = 0 ;  

    MultiFlowDispatcher * dispatcher() const { return _mfd; };  

    /* MultiFlowHandler: stuff to dispatch the outputs, especially when
     * connected to another MultiFlowDispatcher */ 

    private: 

    MultiFlowHandler() { };
    IPFlowID	   _flowid; 
    int		   q_membership; 
    int		   _direction; 
    MultiFlowDispatcher * _mfd;


    /* The signals needed for pull outputs */ 
    bool _can_pull[2]; 

    private: 
    class Port { 
	public: 
	operator MultiFlowHandler * () { return _neighbor;} 
	operator bool() { return _neighbor;} 
	void connect(MultiFlowHandler * mfh, int port) { 
	    	_neighbor = mfh; _remote_port = port; 
	} 
	Packet * pull();  
	void push(Packet * p); 
	unsigned char dispatch_mode() { return _dispatch_mode; } 
	unsigned char dispatch_mode(unsigned char m){ return _dispatch_mode = m; } 
	int remote_port() const { return _remote_port;} 

	private:
	MultiFlowHandler * _local;
	MultiFlowHandler * _neighbor; 
	int 	_remote_port; 
	int 	_local_port; 
	unsigned char _dispatch_mode; 
	friend class MultiFlowHandler; 
    };  

    Port _ports[2][2]; 

    int get_neighbor_port(const int direction, const MultiFlowHandler * const neighbor) { 
	if (neighbor == _ports[direction][0]) 
	    return 0; 
	if (neighbor == _ports[direction][1]) 
	    return 1; 
	return -1; 
    } 
    void remove_neighbor(const MultiFlowHandler *const); 

    protected: 
    Port & input (const int port) { return _ports[0][port]; } 
    Port & output(const int port) { return _ports[1][port]; } 
   
    unsigned char input_port_dispatch(const int port); 
    unsigned char output_port_dispatch(const int port);


    virtual MFHState set_state(const MFHState new_state, const int input_port = -1); 
    MFHState set_state(const MFHState, const MultiFlowHandler * const );
    MFHState handler_state(){ return _handler_state; } 

    private: 
    	MFHState _handler_state; 
	int verbosity () const; 

    friend class MultiFlowDispatcher; 
};

typedef HashTable<IPFlowID,MultiFlowHandler*>::iterator MFHIterator; 

class MultiFlowDispatcher : public Element { 

    friend class MultiFlowHandler;

    public: 
	MultiFlowDispatcher() 
	{
	    int i; 
	    for (i = 0; i < NUM_QUEUES; i++) { 
		mfd_queues[i].set_mfd(this);
		mfd_queues[i].set_qid(i);  
	    }
	    for ( i = 0; i <=1; i++) { 
		_output_port_neighbor_port[i] = -2; 
	    } 
	} ; 
	virtual ~MultiFlowDispatcher() {/*FIXME: delete all handlers*/ } ; 

	virtual const char * mfh_processing() const ; 

	/** @brief push a packet
	* 
	* This is the implementation of Element::push
	* Under all normal circumstances this method should neither be 
	* modified or called by the user directly. */
	virtual void push(int port, Packet *p); 

	/** @brief push a packet
	* 
	* This is the implementation of Element::push
	* Under all normal circumstances this method should neither be 
	* modified or called by the user directly. */
	virtual Packet *pull(int port); 

	/** @brief configures the Element
	* 
	* See Element::configure about this method. 
	* You should overwrite it, but call MultiFlowDispatcher::configure
	* in your implementation */
	virtual int configure(Vector<String> &conf, ErrorHandler *errh);

	/** @brief initialized the Element
	* 
	* See Element::initialize about this method
	* There is usually no need to overwrite this function, but if you
	* do so, make sure to call MultiFlowDispatcher::initialize 
	*/
	virtual int initialize(ErrorHandler *errh); 

	/** @brief Iterator to all the handlers
	* 
	* @return MFHIterator over all registered MultiFlowHandlers
	* in random order */
	MFHIterator all_handlers_iterator() { return mfd_hash.begin(); }

	/** @brief The number of TCPConnections
	 * 
	 * @return The number of MultiFlowHandler instances tracked by the
	 * MultiFlowDispatcher
	 */
	int num_connections() { 
		int result = 0;
		MFHIterator it = mfd_hash.begin();	
			while(it) {
				++it;
				result++;
			}
		return result;
	}

	int verbosity() { return _verbosity; }

//	/** @brief A wrapper for click_chatter for debug output
//	 * 
//	 * Takes a bitmask and outputs various types of debug messages based
//	 * on bitwise matches against the _verbosity flags set by configure
//	 */
//	inline void debug_output(int bitmask, const char *fmt, ...) {
//		va_list val;  
//		va_start(val, fmt); 
//
//		if (bitmask & _verbosity) { 
////			click_chatter("bitmask: [%x], verb: [%x]", bitmask, _verbosity);
//			vclick_chatter(fmt, val );
//		} 
//		va_end(val); 
//	};

	MultiFlowHandler * create_handler(int port, const IPFlowID &flowid); 
	bool connect_handlers(MultiFlowHandler * local_mfh, MultiFlowHandler * remote_mfh); 

    protected: 
	// following method was declared const, but g++ ignores this
	ActiveNotifier * empty_note() { return &_empty_note; }

    private: 
	ActiveNotifier _empty_note; 
	/** @brief return a newly generated MultiFlowHandler
	*
	* This should always be overwritten to return an object of 
	* the correct derivate of MultiFlowHandler. 
	*/
	virtual MultiFlowHandler * new_handler(const IPFlowID & flowid, const int direction) = 0;  
	
	/** @brief deletes a MultiFlowHandler
	* 
	* @param mfh The handler that is to be deleted. 
	* 
	* This method removes a handler from all queues. It should always 
	* be called from any MultiFlowHandler destructor. 
	*/
	void remove_handler(MultiFlowHandler * mfh); 


	/** @brief check whether this packet can create a new connection
	* 
	* @param packet The packet to check
	* 
	* This can be overwritten, if the protocol has dedicated "syn"
	* packets. (e.g. tcp checks for "exactly syn flag set")
	* additional actions (such as sending a reset) can also be
	* performed here 
	*
	* The default returns always true. 
	* 
	* 
	*/
	virtual bool is_syn(const Packet * ); 

	/* MultiFlowDispatcher: Stuff for the queues */ 
    protected:
	class HandlerQueue { 

		public: 

		HandlerQueue() {}; 
		HandlerQueue(MultiFlowDispatcher * m, int qi) {
		   	mfd = m;
			qid = qi;
			q = NULL;
		}

		void set_mfd(MultiFlowDispatcher *m) { mfd = m; }
		MultiFlowDispatcher * get_mfd() { return mfd; }
		void set_qid(int q) { qid = q; }
		int  get_qid() { return qid; }
		int  verbosity() { return get_mfd()->verbosity(); }

		void enqueue(MultiFlowHandler *qe);
		void dequeue(MultiFlowHandler *qe); 
		bool is_empty() { return q ? false : true; }
		MultiFlowHandler * get(); 

	    private:

		MultiFlowDispatcher * mfd; 
		MultiFlowHandler   	* q; 
		int qid; 
	};

    protected:
	MultiFlowHandler * mfd_queue_pull(int qid) {
		return mfd_queues[qid].get();
	}

	void mfh_delete(MultiFlowHandler * h) { 
	    mfd_queues[QID_DELETE].enqueue(h); 
	}
/* 	void set_mfd_id(const int port, const Packet * const p); */


	void mfh_unset_pullable(MultiFlowHandler * h, int port);
	void mfh_set_pullable(MultiFlowHandler * h, int port); 
	bool is_pullable(const int port) { 
		debug_output(VERB_DEBUG, "[%s] mfd::is_pullable port [%d]: [%s]", name().c_str(), port, ((! mfd_queues[QID_PULLABLE_BASE + port].is_empty()) ? "true" : "false")); 
	    return (! mfd_queues[QID_PULLABLE_BASE + port].is_empty()); 
	}
	
	/*MultiFlowDispatcher: Stuff for the hash */

    private: 
	int _verbosity;
	HandlerQueue  mfd_queues[NUM_QUEUES]; 
	HashTable<IPFlowID, MultiFlowHandler*> mfd_hash; 
/*	IPFlowID 	_mfd_id; *Reused, do not allocate one per packet*/
	MultiFlowHandler * get_mfh(const int dir, Packet *p); 
	MultiFlowHandler * get_mfh(const int dir, const IPFlowID &flowid, Packet *p = NULL ); 

	/* stuff for dispatching to other MFD */
 	enum Processing { MFH_VAGNOSTIC, MFH_VPUSH, MFH_VPULL };

	int get_neighbor_port(const bool input, const MultiFlowDispatcher * const neighbor); 

	void mfh_processing_vector(int*, int* , ErrorHandler* ) const; 
	static int mfh_next_processing_code(const char*& p, ErrorHandler* errh); 


#define MFD_DISPATCH_INVALID		0x00

#define MFD_DISPATCH_MODE		0x0f
#define MFD_DISPATCH_PUSH 		0x01
#define MFD_DISPATCH_PULL 		0x02
#define MFD_DISPATCH_QUEUE		0x03
#define MFD_DISPATCH_DEQUEUE		0x04

#define MFD_DISPATCH_SCHEDULER		0xf0
#define MFD_DISPATCH_ELEMENT		0x10
#define MFD_DISPATCH_MFD_DIRECT 	0x20

	unsigned char _input_port_dispatch[2];
	unsigned char _output_port_dispatch[2];
    
    public:
	unsigned char input_port_dispatch(const int port){return _input_port_dispatch[port]; } 
	unsigned char output_port_dispatch(const int port){return _input_port_dispatch[port]; } 

	MultiFlowDispatcher * _output_port_neighbors[2]; 
	MultiFlowDispatcher * _input_port_neighbors[2]; 
	int _output_port_neighbor_port[2]; 
    private:

	NotifierSignal _input_pull_signal[2]; 
	Task 	       * _input_pull_task[2]; 
    public: 
    	virtual bool run_task(Task *); 
	unsigned char dispatch_code(const bool input, const int port) { 
	        assert(! (port & ~1 )  ); 
		return input ? _input_port_dispatch[port] : _output_port_dispatch[port] ; 
	} 

};

inline void 
MultiFlowDispatcher::mfh_unset_pullable(MultiFlowHandler *h, const int port) { 
    mfd_queues[QID_PULLABLE_BASE + port].dequeue(h); 
}

inline void 
MultiFlowDispatcher::mfh_set_pullable(MultiFlowHandler *h, const int port) { 
    mfd_queues[QID_PULLABLE_BASE + port].enqueue(h); 
	StringAccum sa; 
	sa << h->flowid();
	debug_output(VERB_DEBUG, "[%s] mfd::mfh_set_pullable enqueing new mfh [%s] on port [%d], calling wake", name().c_str(), sa.c_str(), port); 
    _empty_note.wake(); 
}

inline void 
MultiFlowHandler::Port::push(Packet *p){ 
       /* TODO: this only covers MFD_DISPATCH_ELEMENT */
    	_local->dispatcher()->output(_local_port).push(p); 

} 

inline Packet * 
MultiFlowHandler::Port::pull(){ 

//    	click_chatter("<%x>::input(%u).pull\n", _local, _local_port); 
	
	switch (_local->input_port_dispatch(_local_port) & MFD_DISPATCH_SCHEDULER) { 
	    case MFD_DISPATCH_ELEMENT: 
	    	return _local->dispatcher()->input(_local_port).pull(); 
	    case MFD_DISPATCH_MFD_DIRECT: 
	        return _neighbor ? _neighbor->pull(_remote_port) : NULL; 
	    default: 
	    	return NULL; 
	} 
} 

inline unsigned char 
MultiFlowHandler::input_port_dispatch(const int port)  
{ 
    return dispatcher()->input_port_dispatch(port); 
}  

inline unsigned char 
MultiFlowHandler::output_port_dispatch(const int port) 
{ 
    return dispatcher()->output_port_dispatch(port); 
}  

inline int 
MultiFlowHandler::verbosity() const { 
    return dispatcher()->verbosity(); 
} 


CLICK_ENDDECLS
#endif // CLICK_MULTIFLOWDISPATCHER_HH

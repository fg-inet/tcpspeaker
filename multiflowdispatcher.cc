#include <click/multiflowdispatcher.hh> 
#include <click/straccum.hh>
#include <click/router.hh>
#include <click/routervisitor.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/error.hh> 

/** @file multiflowdispatcher.hh
 * @brief The MultiFlowDispatcher/MultiFlowHandler provides dynamic per-flow handlers
 */

/** @class MultiFlowHandler
 * @brief The base class for Handlers
 * 
 * A MultiFlowHandler is what an Element is in the rest of click, but one
 * is spawend automatically for each distinct IP flow that is seen by the
 * corresponding MultiFlowDispatcher Element.
 * 
 * Note: MultiFlowDispatcher is not derrived from Element, but it
 * has a subset of methods from Elements such as push and pull. 
 * These functions have the same signature as those of the Element.
 * 
 * There is no configure function, configuration is done in the Dispatcher. 
 * If you need configuration parameters, store them in your Dispatcher
 * class and access them through the mfd() function.
 */

CLICK_DECLS
MultiFlowHandler::MultiFlowHandler(
	MultiFlowDispatcher * mfd, 
	const IPFlowID & flowid, 
	const int direction ) : _flowid(flowid),_handler_state(CREATE) 
{
    _mfd = mfd;
    _direction = direction;
    q_membership = 0; 
    StringAccum sa; 
    sa << flowid; 
    for (int inout = 0; inout<=1; inout++){ 
	for (int i = 0; i<=1; i++) { 
	    _ports[inout][i]._local_port = i; 
	    _ports[inout][i]._local = this; 
	    _ports[inout][i]._neighbor = NULL; 
	    if (inout == 0 ) { 
		_ports[inout][i]._dispatch_mode = dispatcher()->input_port_dispatch(i); 
	    } else { 
		_ports[inout][i]._dispatch_mode = dispatcher()->output_port_dispatch(i); 
	    }
	} 
    } 
}


MultiFlowHandler::~MultiFlowHandler() { 
	dispatcher()->remove_handler(this); 

	for(int i =0; i<=1; i++){ 
	    for (int j=0; j<=1; j++){ 
		if (MultiFlowHandler * neighbor = _ports[i][j]._neighbor) { 
		    neighbor->remove_neighbor(this); 
		} 
	    } 
	} 
}
void
MultiFlowHandler::remove_neighbor(const MultiFlowHandler  * const neighbor){ 
	for(int i =0; i<=1; i++){ 
	    for (int j=0; j<=1; j++){ 
		if (neighbor == _ports[i][j]._neighbor) { 
		    _ports[i][j]._neighbor = NULL; 
		    _ports[i][j]._remote_port = -1; 
		} 
	    } 
	} 
} 

void
MultiFlowHandler::set_pullable(int port, bool pullable) { 

    unsigned char code = dispatcher()->dispatch_code(false, port) ; 

    debug_output(VERB_DISPATCH, "set_pullable[%u] code <%hx>\n", port, code); 
    if ( ( code & MFD_DISPATCH_SCHEDULER ) == MFD_DISPATCH_ELEMENT ) {  
	if (pullable) { 
	    dispatcher()->mfh_set_pullable(this, port); 
	} else { 
	    dispatcher()->mfh_unset_pullable(this, port); 
	}
        return; 
    }
    if ( ( code & MFD_DISPATCH_SCHEDULER ) == MFD_DISPATCH_MFD_DIRECT ) {  

	debug_output(VERB_DISPATCH, "set_pullable[%u] %s\n", port, pullable ? "true" : "false"); 

	if ( (code & MFD_DISPATCH_MODE) == MFD_DISPATCH_PULL ) { 

	    /*FIXME: lots of tmp var's for debugging here */
	    
	    MultiFlowDispatcher * tmp_dispatch = dispatcher(); 
	    MultiFlowHandler * neigh = output(port); 

	    debug_output(VERB_DISPATCH, "calling <%x>->can_pull now\n", neigh); 
	    debug_output(VERB_DISPATCH, "neigh has dispatcher <%x> <%s> \n", 
	    	neigh->dispatcher(), neigh->dispatcher()->name().c_str() ); 

	    neigh->can_pull(tmp_dispatch, pullable); 
	} 

	debug_output(VERB_DISPATCH, "set_pullable done\n"); 
	return; 
    } 
    debug_output(VERB_ERRORS | VERB_DISPATCH, "this dispatch code is not implemented in set_pullable \n") ; 
    return; 
}

MFHState
MultiFlowHandler::set_state(
	const MFHState new_state, 
	const MultiFlowHandler * const neighbor
	) 
{ 
    return set_state(new_state, get_neighbor_port(0, neighbor)); 

} 

MFHState
MultiFlowHandler::set_state(const MFHState new_state, const int input ) { 

    if (_handler_state >= new_state) 
	return _handler_state; 

    debug_output(VERB_MFH_STATE, "MFH: set_state[%u] (%u) -> (%u)\n", input, _handler_state, new_state); 
    _handler_state = new_state; 

    if (_handler_state == SHUTDOWN || _handler_state == CLOSE ) {  
	for (int out = 0; out <= 1; out ++) { 
	    if (output(out))
	    	static_cast<MultiFlowHandler*>(output(out))->set_state(_handler_state,this); 
	} 
    }
    return _handler_state; 
} 


/** @class MultiFlowDispatcher
 * @brief The special Element for handling multiple flows
 * 
 * A MultiFlowDispatcher is an Element that spawns new MultiFlowHandlers
 * every time a new flow arrives at any of its ports.
 *
 * It supports uni- and bidirectional flows, unidirectional flows ar
 * supposed to go from port 0 to port 0, if there is a reverse direction it
 * is expected to go from port 1 to port 1. 
 * Implementing these ports as both push and pull in any combination 
 * is supported.
 * 
 * <h3> Flow of packets </h3> 
 *  
 * This shows how packets are dispatched in the pull-push case
 * 
 * <pre>
 *       +---- HandlerQueues -----------------------------+
 *       |           +----------+                         |
 *       |         +----------+ |                         |
 *       |       +----------+ | |    +----------+         |
 *       |       |MultiFlow | | |    |MultiFlow |         |
 *       |   push|Handler   | | |    |Handler   |pull     |
 *       |  +---->          > |-+    >          >-----+   |
 *       |  |    | flowid A |-+      | flowid B |     |   |
 *       |  |    +----------+        +----------+     |   |
 *       +- | ------------------------- ^ ----------- | --+
 *          |                           |             |
 *          ---------\                  |       /-----/
 *                   |                  |       |
 *               +--------------------------------+
 *               | MultiFlowDispatcher  |       | |
 *               |   |                  |       | |
 *           push|+------+            +--------+| |pull
 *       -------->|hash  |            |pullable|+->-------- 
 *               ||lookup|            |queue   |  |
 *               ||flowid|            |roundrob|  |
 *               |+------+            +--------+  |
 *               |                                |
 *               +--------------------------------+
 * </pre>
 * 
 * Other cases are not yet implemented, but straight forward.
 * TODO: MultiFlowDispatcher should provide a wrapper for pull
 *       outputs, this is a one-liner
 * TODO: MultiFlowDispatcher should have a loop to pull upstream 
 *       Elements, and push the packets to Handlers
 * TODO: Provide an interface that Handlers can send a choke signal 
 *       to upstream Handlers to in case two Dispatchers are connected.
 *       
 */ 



void    
MultiFlowDispatcher::push(int port, Packet *p)
{
   MultiFlowHandler *mfh = get_mfh(port, p); 
   
    if (!mfh) { 
		p->kill(); 
		return; 
    }
    mfh->push(port, p); 
}

Packet *
MultiFlowDispatcher::pull(int port)
{ 
	MultiFlowHandler *mfh = NULL;
	Packet *p = NULL; 
	StringAccum sa;   

	if (! is_pullable(port)) {
		debug_output(VERB_PACKETS, "[%s] mfd::pull port [%d] mfd_queue is empty: nothing to pull", name().c_str(), port); 
	    goto empty; 
	}

	while (!p) {
		mfh = mfd_queue_pull(QID_PULLABLE_BASE + port);
		if (!mfh) { 
			debug_output(VERB_PACKETS, "[%s] mfd::pull no mfh exists in the mfd: nothing to pull", name().c_str()); 
		    goto empty; 
		}
		p = mfh->pull(port); 

		if (!p) { 
			debug_output(VERB_PACKETS, "[%s] mfd::pull no mfh exists in the mfd: nothing to pull", name().c_str()); 
			mfh_unset_pullable(mfh,port); 
		}
	}
	
	sa << mfh->flowid(); 
	debug_output(VERB_PACKETS, "[%s] mfd::pull [%s]\n", name().c_str(), sa.c_str()); 
	return p; 

	empty:
		debug_output(VERB_PACKETS, "[%s] mfd::pull empty: calling notifier.sleep()", name().c_str()); 
		_empty_note.sleep(); //FIXME: other port may be still pullable 
		return NULL; 
}


int 
MultiFlowDispatcher::configure(Vector<String> &conf, ErrorHandler *errh __attribute__((unused)) ) 
{ 
	_empty_note.initialize(Notifier::EMPTY_NOTIFIER, router()); 
	// parse out the verbosity paramater as passed to the element on click
	// invocation
	if (cp_va_kparse(conf, this, errh, 
			"VERBOSITY", 0, cpUnsigned, &(_verbosity), 
			cpIgnoreRest,	
			cpEnd) < 0) 
		return -1;

	// following conditional fixes compiler unused var warnings
	if (&conf == NULL && errh == NULL) { errh = NULL; }
	return 0; 
}

int 
MultiFlowDispatcher::initialize(ErrorHandler * errh ) { 

    Element::initialize(errh); 
    ElementNeighborhoodTracker tracker(router());
    Vector<Element *> neighbors; 

    debug_output(VERB_INFO, "now initializing [%s]", name().c_str()); 

    /* find out about our neighbors and the relationships of push-pull conversion
     * neighbors can be Elements or MultiFlowDispatchers
     *
     * scheduling can be pull/push (if mfd-port and mfh-port processing matches) 
     *   or queue/dequeue (if processing does not match)
     */ 
     
    int i = 0;  

    int in_proc[2]; 
    int out_proc[2]; 
    mfh_processing_vector(in_proc,out_proc, errh); 

    MultiFlowDispatcher * neighbor; 

    for (i=0; i<=1; i++){ 
	tracker.clear(); 
	router()->visit_upstream(this, i, &tracker);
	Vector<Element *> neighbors = tracker.elements(); 
	if (neighbors.size() > 1 ) { 
	    _input_port_dispatch[i] = MFD_DISPATCH_ELEMENT; 
	    _input_port_neighbors[i] = NULL; 
	} else {  
	    if (( neighbor = (MultiFlowDispatcher *) neighbors[0]->cast("MultiFlowDispatcher")) ){ 
		_input_port_dispatch[i] = MFD_DISPATCH_MFD_DIRECT; 
	        _input_port_neighbors[i] = neighbor;  
		
	    } else { 
		_input_port_dispatch[i] = MFD_DISPATCH_ELEMENT; 
	        _input_port_neighbors[i] = NULL; 
	    } 
	} 
	switch (in_proc[i]) { 
	    case MFH_VPUSH: 
		_input_port_dispatch[i] |= input(i).active() ? 
		    MFD_DISPATCH_DEQUEUE : MFD_DISPATCH_PUSH; 
		break; 
	    case MFH_VPULL: 
		_input_port_dispatch[i] |= input(i).active() ? 
		    MFD_DISPATCH_PULL : MFD_DISPATCH_QUEUE; 
		break; 
	    case MFH_VAGNOSTIC: 
		_input_port_dispatch[i] |= input(i).active() ? 
		    MFD_DISPATCH_PULL : MFD_DISPATCH_PUSH; 
		break; 
	}
	debug_output(VERB_DISPATCH, "[%u]%s dispatching code <%hx>\n", 
		i, name().c_str(), _input_port_dispatch[i]); 
    } 
    for (i=0; i<=1; i++){ 
	tracker.clear(); 
	router()->visit_downstream(this, i, &tracker);
	Vector<Element *> neighbors = tracker.elements(); 
	if (neighbors.size() > 1 ) { 
	    _output_port_dispatch[i] = MFD_DISPATCH_ELEMENT; 
	    _output_port_neighbors[i] = NULL; 
	} else {  
	    if ( (neighbor = (MultiFlowDispatcher *)neighbors[0]->cast("MultiFlowDispatcher")) ){ 
		_output_port_dispatch[i] = MFD_DISPATCH_MFD_DIRECT; 
		_output_port_neighbors[i] = neighbor; 
	    } else { 
		_output_port_dispatch[i] = MFD_DISPATCH_ELEMENT; 
		_output_port_neighbors[i] = NULL; 
	    } 
	} 
	switch (out_proc[i]) { 
	    case MFH_VPUSH: 
		_output_port_dispatch[i] |= output(i).active() ? 
		    MFD_DISPATCH_PUSH : MFD_DISPATCH_DEQUEUE; 
		break; 
	    case MFH_VPULL: 
		_output_port_dispatch[i] |= output(i).active() ? 
		    MFD_DISPATCH_QUEUE : MFD_DISPATCH_PULL; 
		break; 
	    case MFH_VAGNOSTIC: 
		_output_port_dispatch[i] |= output(i).active() ? 
		    MFD_DISPATCH_PUSH : MFD_DISPATCH_PULL; 
		break; 
	}

	debug_output(VERB_DISPATCH, "%s[%u] dispatching code <%hx>\n", 
		name().c_str(), i, _output_port_dispatch[i]); 
    } 

    for (i=0; i<=1; i++) { 
	if ( (_input_port_dispatch[i] & MFD_DISPATCH_MODE) == MFD_DISPATCH_DEQUEUE ) { 
	     _input_pull_task[i] = new Task(this); 
	     ScheduleInfo::initialize_task(this, _input_pull_task[i], true, errh); 
	     _input_pull_signal[i] = Notifier::upstream_empty_signal(this, i, _input_pull_task[i]); 
	} 
    } 

    return 0; 
} 

bool
MultiFlowDispatcher::run_task(Task * task)
{
  
  debug_output(VERB_DEBUG, "MultiFlowDispatcher::run_task\n"); 
  int pull_port; 

  if ( task == _input_pull_task[0]) { 
      pull_port = 0;
  } else if (  task == _input_pull_task[1]) { 
      pull_port = 1;
  } else { 
      return false; 
  } 

  debug_output(VERB_DEBUG, "MultiFlowDispatcher::run_task pull from [%u]\n", pull_port); 
  if ( Packet *p = input(pull_port).pull()) { 
	push(pull_port, p); 
	if (_input_pull_signal[pull_port])  
		_input_pull_task[pull_port]->fast_reschedule(); 
 	return true; 	
  } else { 
	return false; 
  } 

}

void 
MultiFlowDispatcher::HandlerQueue::enqueue(MultiFlowHandler *qe) 
{ 
	MultiFlowDispatcher *mymfd = get_mfd();
	debug_output(VERB_MFD_QUEUES, "[%s] mfd::enqueue: method invoked", mymfd->name().c_str());
	/* if connection is already member of me: do nothing */ 
	if (qe->is_q_member(qid)) {
		debug_output(VERB_MFD_QUEUES, "mfd::enqueue: is not a member");
		return;
	}

	debug_output(VERB_MFD_QUEUES, "[%s] mfd::enqueue: point 1 (the mfh is a member)", mymfd->name().c_str()); 
	/* at least one element in queue */ 
	if (! is_empty()) { 
		debug_output(VERB_MFD_QUEUES, "[%s] mfd::enqueue: (q is not empty)", mymfd->name().c_str()); 
		/* Enqueue behind the Handler Queue's' q pointer. *q points to the last
		 * MultiFlowHandler which was inserted into the HandlerQueue */
		qe->next[qid] = q;
		qe->prev[qid] = q->prev[qid];
		qe->prev[qid]->next[qid] = qe; 
		q->prev[qid] = qe;
	} else { 
	debug_output(VERB_MFD_QUEUES, "[%s] mfd::enqueue: point 2 (q is empty)", mymfd->name().c_str());
		q = qe->next[qid] = qe->prev[qid] = qe; 
	}

	debug_output(VERB_MFD_QUEUES, "[%s] mfd::enqueue: calling set_q_membership", mymfd->name().c_str());
	qe->set_q_membership(qid); 
}


void 
MultiFlowDispatcher::HandlerQueue::dequeue(MultiFlowHandler *qe) 
{
    /* do nothing if qe is not in this queue */
    if (! qe->is_q_member(qid)) {
		return; 
	}
    /* if this is the last element in queue, mark queue empty */
	// TODO: To be on the safe side, this should probably be: if (qe == qe->next[qid] && qe == qe->prev[qid]) { 
    if (qe == qe->next[qid]) { 
		debug_output(VERB_MFD_QUEUES, "[%x] mfd::dequeue: q is now null", this); 
		q = NULL; 
	/* queue has some members left, dequeue */
    } else { 
		qe->next[qid]->prev[qid] = qe->prev[qid];
		qe->prev[qid]->next[qid] = qe->next[qid];
		debug_output(VERB_MFD_QUEUES, "[%x] mfd::dequeue: removed qe [%s]", this, qe); 
    }
    /* mark qe as member of no queue */
    qe->next[qid] = NULL; 
    qe->prev[qid] = NULL; 
    qe->del_q_membership(qid); 
}  

bool
MultiFlowDispatcher::is_syn(const Packet *) 
{ 
    return true; 
} 

MultiFlowHandler * 
MultiFlowDispatcher::HandlerQueue::get() { 
	if (!q) 
	    return NULL; 
	MultiFlowHandler * retval = q; 
	q = q->next[qid]; 
	return retval; 
}

int
MultiFlowDispatcher::get_neighbor_port(const bool input, const MultiFlowDispatcher * const neighbor) { 
	if(input) { 
		if ( neighbor == _input_port_neighbors[0] ) 
		    return 0; 
		if ( neighbor == _input_port_neighbors[1] ) 
		    return 1; 
 	} else { 
		if ( neighbor == _output_port_neighbors[0] ) 
		    return 0; 
		if ( neighbor == _output_port_neighbors[1] ) 
		    return 1; 
	} 
	return -1;
} 

MultiFlowHandler * 
MultiFlowDispatcher::get_mfh(const int port, Packet *p) { 

	MultiFlowHandler *mfh; 
	IPFlowID mfh_id(p, (port == 1) ); 
	mfh = get_mfh(port, mfh_id, p); 
	return mfh; 
}


MultiFlowHandler * 
MultiFlowDispatcher::get_mfh(const int port, const IPFlowID  &flow_id, Packet * p ) { 
	
	MultiFlowHandler *mfh; 

	debug_output(VERB_DEBUG, "[%s] mfd::get_mfh: port [%d]", name().c_str(), port); 

	mfh = mfd_hash.get(flow_id); 
	
	debug_output(VERB_DEBUG, "[%s] mfd::get_mfh: handler [%x]: %s", name().c_str(), mfh, mfh?"found":"not found"); 

	// TODO this is where I would filter based on TCP SYN flag and NOT create a
	// new entry in the MFD handler queue UNLESS it's a valid SYN. new_handler
	// needs to return a packet so we can inspect it for syn flag though.

	if (!mfh) { 

	    debug_output(VERB_DISPATCH, "[%s] no suitable handler found \n", name().c_str());  
	    
	    if ( p && ( ! is_syn(p))  ) {  
		return NULL; 
	    } 

	    mfh = create_handler(port, flow_id ); 
	    
    	    if ( (_output_port_dispatch[port] & MFD_DISPATCH_SCHEDULER) == MFD_DISPATCH_MFD_DIRECT ) { 
		MultiFlowDispatcher * remote_mfd = _output_port_neighbors[port]; 
		int remote_input = remote_mfd->get_neighbor_port(true, this); 
		
		/* This assumes that the neighbor is connected 1-1 by using
		 * same packet semantics */ 
		MultiFlowHandler * remote_mfh = remote_mfd->get_mfh(remote_input, remote_input ? flow_id.reverse(): flow_id ); 
		
	        debug_output(VERB_DISPATCH, "[%s] connecting handlers <%x> - <%x> \n", 
			name().c_str(), mfh, remote_mfh); 
		connect_handlers(mfh, remote_mfh); 
		remote_mfd->connect_handlers(remote_mfh, mfh); 
	    } 
	    debug_output(VERB_DISPATCH, "[%s] initializing handler <%x>\n",  
			name().c_str(), mfh); 
	    mfh->set_state(INITIALIZE, port); 
	}
	return mfh; 
} 


MultiFlowHandler * 
MultiFlowDispatcher::create_handler(int port, const IPFlowID &flowid) { 
    MultiFlowHandler * mfh; 

    mfh = new_handler(flowid, port);
    
    debug_output(VERB_DISPATCH, "%s got new handler <%x>\n", name().c_str(), mfh); 
    mfd_hash[flowid] = mfh; 

    return mfh; 
} 



bool 
MultiFlowDispatcher::connect_handlers(MultiFlowHandler * local_mfh, MultiFlowHandler * remote_mfh ) { 

	bool retval = false; 
	MultiFlowDispatcher * remote_mfd = remote_mfh->dispatcher(); 
	
	int local_output = get_neighbor_port(false, remote_mfd); 
	int local_input  = get_neighbor_port(true, remote_mfd); 

	if (local_output > -1 ) { 
	    	int remote_port = remote_mfd->get_neighbor_port(true, this); 
		debug_output(VERB_DISPATCH, "[%s] connecting out[%u] to <%x>[%u]\n", 
			name().c_str(), local_output,
			remote_mfh, remote_port); 
		local_mfh->output(local_output).connect(remote_mfh, remote_port); 
		retval = true; 
	} 

	if (local_input > -1 ) { 
	    	int remote_port = remote_mfd->get_neighbor_port(false, this); 
		debug_output(VERB_DISPATCH, "[%s] connecting [%u]in to <%x>[%u]\n", 
			name().c_str(), local_input,
			remote_mfh, remote_port); 
	    	local_mfh->input(local_input).connect(remote_mfh, remote_port); 
		retval = true; 
	} 
	return retval; 
} 

void 
MultiFlowDispatcher::remove_handler(MultiFlowHandler *mfh) {
	debug_output(VERB_MFD_QUEUES, "[%s] mfd::remove_handler removing mfh [%x] from all handlerqueues", name().c_str(), mfh);
	for (int i=0; i<NUM_QUEUES; i++) { 
		mfd_queues[i].dequeue(mfh); 
	}
	mfd_hash.erase(*(mfh->flowid())); 
}

/* mfh_processing_vector duplicates functionality 
 * of the Element::non-mfh function
 * This is ugly, it would be better to patch Element::processing_vector to take 
 * the processing string as argument */ 
void
MultiFlowDispatcher::mfh_processing_vector(int* in_v, int* out_v, ErrorHandler* errh) const
{
    const char* p_in = mfh_processing();
    int val = 0;

    const char* p = p_in;
    int last_val = 0;
    for (int i = 0; i < ninputs(); i++) {
        if (last_val >= 0)
            last_val = mfh_next_processing_code(p, errh);
        if (last_val >= 0)
            val = last_val;
        in_v[i] = val;
    }

    while (*p && *p != '/')
        p++;
    if (!*p)
        p = p_in;
    else
        p++;

    last_val = 0;
    for (int i = 0; i < noutputs(); i++) {
        if (last_val >= 0)
            last_val = mfh_next_processing_code(p, errh);
        if (last_val >= 0)
            val = last_val;
        out_v[i] = val;
    }
}

int
MultiFlowDispatcher::mfh_next_processing_code(const char*& p, ErrorHandler* errh)
{
    switch (*p) {

      case 'h': case 'H':
	p++;
	return MultiFlowDispatcher::MFH_VPUSH;

      case 'l': case 'L':
	p++;
	return MultiFlowDispatcher::MFH_VPULL;

      case 'a': case 'A':
	p++;
	return MultiFlowDispatcher::MFH_VAGNOSTIC;

      case '/': case 0:
	return -2;

      default:
	if (errh)
	    errh->error("bad processing code");
	p++;
	return -1;

    }
}

const char * 
MultiFlowDispatcher::mfh_processing() const
{
	return "a"; 
} 


CLICK_ENDDECLS
EXPORT_ELEMENT(MultiFlowDispatcher)

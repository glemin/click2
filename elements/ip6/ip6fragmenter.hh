#ifndef CLICK_IP6FRAGMENTER_HH
#define CLICK_IP6FRAGMENTER_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <clicknet/ip6.h>

CLICK_DECLS

/*
 * =c
 * IP6Fragmenter(MTU)
 * =s ip6
 *
 * =d
 * Expects IP6 packets as input.
 * If the IP6 packet size is <= mtu, just emits the packet on output 0.
 * If the size is greater than mtu, splits into fragments emitted on 
 * output 0.
 *
 * =e
 * Example:
 *
 * InfiniteSource(LIMIT 1, LENGTH 6000)
 * -> UDPIP6Encap(fa80::0202:b3ff:fe1e:8329, 1200, f880::0202:b3ff:fe1e:0002, 1201)
 * -> IP6Fragmenter(MTU 1400)          // 0, 1952
 * -> EtherEncap(0x86dd, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
 * -> Discard;
 */

class IP6Fragmenter : public Element {

  uint32_t _MTU;        // maximum transmission unit; this is the maximum payload the layer 2 protocol we use can handle;
                        // in case of IPv6 we need to choose the _MTU so it is equal to the minimal MTU of all MTU's on the path
                        // to the destination
  uint32_t _fragment_size;  // size of each fragment sent over the network
  
  int _drops;
  int _fragments;

  void fragment(Packet *);
  //int optcopy(const click_ip6 *ip1, click_ip6 *ip2);
  
  uint32_t _id; // current fragmentation ID
  
  uint32_t get_length_of_and_update_unfragmentable_part(click_ip6* p, uint8_t& nxt);

 public:

  IP6Fragmenter();
  ~IP6Fragmenter();

  const char *class_name() const		{ return "IP6Fragmenter"; }
  const char *port_count() const		{ return PORTS_1_1X2; }
  const char *processing() const		{ return PUSH; }
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  int drops() const				{ return _drops; }
  int fragments() const				{ return _fragments; }

  void add_handlers() CLICK_COLD;

  void push(int, Packet *p);


};

CLICK_ENDDECLS
#endif

#ifndef CLICK_FIXUDPCHECKSUM_HH
#define CLICK_FIXUDPCHECKSUM_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/udp.h>
CLICK_DECLS

/*
=c

FixUDPChecksum()

=s udp

fixes UDP checksum for IPv6 packets

=d

Fixes the UDP checksum for IPv6 packets. Expects that the network header pointer and 
transport header pointer are set. Most of the time they are already set with the 
IP6Encap element. However if they were not set and an IP6 header is already present,
they can also be set with the MarkIP6Header or CheckIP6Header elements.

=e
  A typical example can be found below. A packet with sample data is created 
  with InfiniteSource(LIMIT 1). After which it got an UDP header, an IP6 header 
  and then the UDP Checksum is fixed.
  
  InfiniteSource(LIMIT 1)
      -> UDPEncap(1200,1500)
      -> IP6Encap(SRC fa80::0202:b3ff:fe1e:8329, DST f880::0202:b3ff:fe1e:0002, PROTO 17)
      -> FixUDPChecksum
      -> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
      -> ToDump("ip6.dump")

=a Strip, IPEncap, IP6Encap, HopByHopEncap, DestinationOptionsEncap, RoutingEncap, FragmentEncap
*/

class FixUDPChecksum : public Element { public:

    FixUDPChecksum() CLICK_COLD;
    ~FixUDPChecksum() CLICK_COLD;

    const char *class_name() const	{ return "FixUDPChecksum"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const		{ return "A"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

    Packet *simple_action(Packet *);

};

CLICK_ENDDECLS
#endif

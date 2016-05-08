#ifndef CLICK_HOPBYHOPENCAP_HH
#define CLICK_HOPBYHOPENCAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * HopByHopEncap(PROTO, [LEN])
 * =s ip6
 *
 * =d
 *
 * Encapsulates the packet in a Hop-By-Hop Extension header with its additional
 * beyond standard length indicated by Len. The Options and padding fields will 
 * all be set to zero.
 *
 * See RouterAlertEncap for a specific Hop-By-Hop Extension header whose Options 
 * and padding fields are not all set to zero.
 *
 * =e
 * A typical example can be found below. A packet with sample data is created 
 * with InfiniteSource(LIMIT 1). After which it got an UDP header, then a 
 * Hop-by-Hop header, then a IP6 header and then the UDP Checksum is fixed
 * (that is, set correctly).
 * 
 * InfiniteSource(LIMIT 1)
 *     -> UDPEncap(1200,1500)
 *     -> HopByHopEncap(PROTO 17)
 *     -> IP6Encap(SRC fa80::0202:b3ff:fe1e:8329, DST f880::0202:b3ff:fe1e:0002, PROTO 0)
 *     -> FixUDPChecksum
 *     -> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
 *     -> ToDump("ip6.dump")
 *
 * =a RouterAlertEncap, IP6Encap, UDPEncap, FixUDPChecksum  */

class HopByHopEncap : public Element {
public:
    HopByHopEncap();
    ~HopByHopEncap();

    const char *class_name() const		{ return "HopByHopEncap"; }
    const char *port_count() const		{ return PORTS_1_1; }
    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

    Packet *simple_action(Packet *);
private:
    uint8_t _next_header; // next header following the IPv6 Hop-by-Hop extension header.
    uint8_t _header_ext_length;   // length of this header in 8-octet units, not including the first 8 octets
};

CLICK_ENDDECLS
#endif

#ifndef CLICK_STOREIP6ADDRESS_HH
#define CLICK_STOREIP6ADDRESS_HH
#include <click/element.hh>
#include <click/ip6address.hh>
CLICK_DECLS

/*
=c
StoreIP6Address(OFFSET)
StoreIP6Address(ADDR, OFFSET)
=s ip6
stores IPv6 address in packet
=d

The one-argument form writes the destination IP address annotation into the
packet at offset OFFSET, usually an integer. But if the annotation is zero, it
doesn't change the packet.

The two-argument form writes IPv6 address ADDR into the packet at offset
OFFSET. ADDR can be zero.

The OFFSET argument may be the special string 'ether_src', 'ether_dst, 'src' or 'dst'. 
We use 'ether_src' and 'ether_dst' to set a packet that contains an Ethernet header 
proceded by the IPv6 header, its src and dst address respectively.
We use 'src' and 'dst' to set a packet that contains a raw IPv6 header, its src 
and dst address respectively.

If the OFFSET lets the element write an IPv6 address out of range, a segmentation fault 
happens. Be sure that the packets passed are not too small. To guarantee no segmentation 
faults, use the CheckIP6Header element.

=e 
FromHost(ethx)
-> CheckIP6Header // drops packets of less than 40 bytes
-> ip6filter :: IP6Classifier(src host 2001:2:f000::1 and nxt 59, -)

ip6filter[0]
-> DecIP6HLIM
-> StoreEtherAddress(0, 00:0a:95:9d:68:16)
-> StoreIP6Address(2001:2:1::4, 'ether_dst') // write '2001:2:1::4' on bytes '24-40' of the IPv6 header

ip6filter[1]
-> Discard;

=a
CheckIP6Header
*/

class StoreIP6Address : public Element { public:

    StoreIP6Address() CLICK_COLD;
    ~StoreIP6Address() CLICK_COLD;

    const char *class_name() const		{ return "StoreIP6Address"; }
    const char *port_count() const		{ return PORTS_1_1X2; }
    const char *processing() const		{ return PROCESSING_A_AH; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

    Packet *simple_action(Packet *);

  private:
    int _offset;
    IP6Address _address;
    bool _address_given;
};

CLICK_ENDDECLS
#endif

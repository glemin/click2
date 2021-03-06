#ifndef CLICK_FRAGMENTATIONENCAP_HH
#define CLICK_FRAGMENTATIONENCAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * FragmentationEncap(PROTO, OFFSET, M, [ID])
 * =s ip6
 *
 * =d
 *
 * Encapsulates a packet in a Fragmentation extension.
 *
 * =e
 *
 * InfiniteSource(LIMIT 1)
 *   -> UDPEncap(1200,1500)
 *   -> FragmentationEncap(PROTO 17, OFFSET 0, ID 0, M 0)
 *   -> IP6Encap(SRC fa80::0202:b3ff:fe1e:8329, DST f880::0202:b3ff:fe1e:0002, PROTO 44)
 *   -> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
 *   -> ToDump("ip6.dump")
 *
 */

class FragmentationEncap : public Element {

public:
    FragmentationEncap();
    ~FragmentationEncap();

    const char *class_name() const		{ return "FragmentationEncap"; }
    const char *port_count() const		{ return PORTS_1_1; }
    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

    Packet *simple_action(Packet *);
    
private:
    uint8_t _next_header;               /* next header */
    uint16_t _offset;                   /* Fragment offset */
    uint32_t _identification;           /* Packet identification value, generated by the source node. 
                                           Needed for reassembly of the original packet. */
    bool _more_fragments;               /* 1 means more fragments follow; 0 means last fragment. */
};

CLICK_ENDDECLS
#endif /* CLICK_FRAGMENTATIONENCAP_HH */

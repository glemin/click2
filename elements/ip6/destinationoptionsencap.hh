#ifndef CLICK_DESTINATIONOPTIONSENCAP_HH
#define CLICK_DESTINATIONOPTIONSENCAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * DestinationOptionsEncap([OFFSET])
 * =s ip6
 *
 * =d
 *
 * Encapsulates a packet in a Destination Options extension header with
 * only a padN option.
 *
 * =e
 *
 * InfiniteSource(LIMIT 1)
 *   -> UDPEncap(1200,1500)
 *   -> DestinationOptionsEncap(PROTO 17)
 *   -> IP6Encap(SRC fa80::0202:b3ff:fe1e:8329, DST f880::0202:b3ff:fe1e:0002, PROTO 60)
 *   -> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
 *   -> ToDump("ip6.dump")
 *
 */

class DestinationOptionsEncap : public Element {

public:
    DestinationOptionsEncap();
    ~DestinationOptionsEncap();

    const char *class_name() const		{ return "DestinationOptionsEncap"; }
    const char *port_count() const		{ return PORTS_1_1; }
    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

    Packet *simple_action(Packet *);
    
private:
    uint8_t _next_header;               /* next header */
    uint8_t _header_ext_length;         /* 8-bit unsigned integer.  Length of the
                                           Destination Options header in 8-octet units, not
                                           including the first 8 octets. */
};

CLICK_ENDDECLS
#endif /* CLICK_DESTINATIONOPTIONSENCAP_HH */

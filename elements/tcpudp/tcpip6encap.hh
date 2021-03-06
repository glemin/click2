#ifndef CLICK_TCPIP6ENCAP_HH
#define CLICK_TCPIP6ENCAP_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/tcp.h>
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
CLICK_DECLS

/*
=c

TCPIP6Encap(SRC, SPORT, DST, DPORT)

=s udp

encapsulates packets in static TCP/IP6 headers

=d

Encapsulates each incoming packet in a TCP/IP6 packet with source address
SRC, source port SPORT, destination address DST, and destination port
DPORT. The TCP checksum is always calculated.

As a special case, if DST is "DST_ANNO", then the destination address
is set to the incoming packet's destination address annotation.

The TCPIP6Encap element adds both a UDP header and an IP6 header.

The Strip element can be used by the receiver to get rid of the
encapsulation header.

Keywords arguments are:

=over 8

=item OFF

Data offset in words. Gives how long the TCP header is in 32-bit words. An standard TCP header without extra options has a size of 5 words. The maximum size is 20 words.
Default value is 5

=item SEQ

Integer. Specifies the sequence number of the packet. Default is 0.

=item ACK

Integer. Specifies the ACK field of the packet. Default is 0.

=item FLAGS

Integer. Species the values of the FLAGS field (contains CWR, ECE, URG, ACK, PUSH, RST, SYN and FIN).  Default is 0 (no flags are set).

=item FLAGS2

Integer. Species the value of the other FLAGS field (contains reserved bytes and NS). Default is 0.

=item WIN

Integer. Specifies the value of the window size (in bytes). Default is 0.

=item URG

Integer. Specifies the value of the urgent pointer field. Default is 0 (urgent pointer not set).

=back
    

=e
    InfiniteSource(LIMIT 1)
    -> TCPIP6Encap(SRC fa80::0202:b3ff:fe1e:8329, SPORT 1200, DST f880::0202:b3ff:fe1e:0002, DPORT 1500, OFF 5, FLAGS 1)
    -> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
    -> ToDump("example.dump")

=h src read/write

Returns or sets the SRC source address argument.

=h sport read/write

Returns or sets the SPORT source port argument.

=h dst read/write

Returns or sets the DST destination address argument.

=h dport read/write

Returns or sets the DPORT destination port argument.

=a Strip
*/

class TCPIP6Encap : public Element { public:

    TCPIP6Encap();
    ~TCPIP6Encap();

    const char *class_name() const	{ return "TCPIP6Encap"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const		{ return "A"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const	{ return true; }
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

  private:

    struct in6_addr _saddr; /* ip6 source address */
    struct in6_addr _daddr; /* ip6 destination address */
    uint16_t _sport;    /* source port */
    uint16_t _dport;    /* destination port */
    bool _use_dst_anno;     /* are we using the destination address stored in the destination annotation space? */
    tcp_seq_t _seq;  /* sequence number */
    tcp_seq_t _ack;  /* acknowledgement number */
    unsigned _off; /* data offset in words; specifies the size of the TCP header in 32 bit words; minimum size is 5 words and the maximum size 15 words */
    unsigned _flags2; /* more flags */
    uint8_t	_flags;   /* flags */
    uint16_t _win;   /* window */
    uint16_t _sum;   /* checksum */
    uint16_t _urp;   /* urgent pointer */
    
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    bool _aligned;
    bool _checked_aligned;
#endif

    static String read_handler(Element *, void *) CLICK_COLD;


};

CLICK_ENDDECLS
#endif

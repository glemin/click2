#ifndef CLICK_IP6FILTER_HH
#define CLICK_IP6FILTER_HH
#include "elements/standard/classification.hh"
#include <click/element.hh>
#include <click/vector.hh>
#include "ip6filterAST.hh"

CLICK_DECLS

/*
=c

IPFilter(ACTION_1 PATTERN_1, ..., ACTION_N PATTERN_N)

=s ip

filters IP packets by contents

=d

Filters IP packets. IPFilter can have an arbitrary number of filters, which
are ACTION-PATTERN pairs. The ACTIONs describe what to do with packets,
while the PATTERNs are tcpdump(1)-like patterns; see IPClassifier(n) for a
description of their syntax. Packets are tested against the filters in
order, and are processed according to the ACTION in the first filter that
matched.

Each ACTION is either a port number, which specifies that the packet should be
sent out on that port; 'C<allow>', which is equivalent to 'C<0>'; or 'C<drop>'
, which means drop the packet. You can also say 'C<deny>' instead of
'C<drop>', but see the compatibility note below.

The IPFilter element has an arbitrary number of outputs. Input packets must
have their IP header annotation set; CheckIPHeader and MarkIPHeader do
this.

=n

Every IPFilter element has an equivalent corresponding IPClassifier element
and vice versa. Use the element whose syntax is more convenient for your
needs.

B<Compatibility note>: 'C<deny>' formerly meant 'C<1>' if the element had at
least two outputs and 'C<drop>' if it did not. We decided this was
error-prone; now it just means 'C<drop>'. For now, however, 'C<deny>' will
print a warning if used on an element with more than one output.

=e

This large IPFilter implements the incoming packet filtering rules for the
"Interior router" described on pp691-692 of I<Building Internet Firewalls,
Second Edition> (Elizabeth D. Zwicky, Simon Cooper, and D. Brent Chapman,
O'Reilly and Associates, 2000). The captialized words (C<INTERNALNET>,
C<BASTION>, etc.) are addresses that have been registered with
AddressInfo(n). The rule FTP-7 has a port range that cannot be implemented
with IPFilter.

  IPFilter(// Spoof-1:
           deny src INTERNALNET,
           // HTTP-2:
           allow src BASTION && dst INTERNALNET
              && tcp && src port www && dst port > 1023 && ack,
           // Telnet-2:
           allow dst INTERNALNET
              && tcp && src port 23 && dst port > 1023 && ack,
           // SSH-2:
           allow dst INTERNALNET && tcp && src port 22 && ack,
           // SSH-3:
           allow dst INTERNALNET && tcp && dst port 22,
           // FTP-2:
           allow dst INTERNALNET
              && tcp && src port 21 && dst port > 1023 && ack,
           // FTP-4:
           allow dst INTERNALNET
              && tcp && src port > 1023 && dst port > 1023 && ack,
           // FTP-6:
           allow src BASTION && dst INTERNALNET
              && tcp && src port 21 && dst port > 1023 && ack,
           // FTP-7 omitted
           // FTP-8:
           allow src BASTION && dst INTERNALNET
              && tcp && src port > 1023 && dst port > 1023,
           // SMTP-2:
           allow src BASTION && dst INTERNAL_SMTP
              && tcp && src port 25 && dst port > 1023 && ack,
           // SMTP-3:
           allow src BASTION && dst INTERNAL_SMTP
              && tcp && src port > 1023 && dst port 25,
           // NNTP-2:
           allow src NNTP_FEED && dst INTERNAL_NNTP
              && tcp && src port 119 && dst port > 1023 && ack,
           // NNTP-3:
           allow src NNTP_FEED && dst INTERNAL_NNTP
              && tcp && src port > 1023 && dst port 119,
           // DNS-2:
           allow src BASTION && dst INTERNAL_DNS
              && udp && src port 53 && dst port 53,
           // DNS-4:
           allow src BASTION && dst INTERNAL_DNS
              && tcp && src port 53 && dst port > 1023 && ack,
           // DNS-5:
           allow src BASTION && dst INTERNAL_DNS
              && tcp && src port > 1023 && dst port 53,
           // Default-2:
           deny all);

=h program read-only
Returns a human-readable definition of the program the IPFilter element
is using to classify packets. At each step in the program, four bytes
of packet data are ANDed with a mask and compared against four bytes of
classifier pattern.

=a

IPClassifier, Classifier, CheckIPHeader, MarkIPHeader, CheckIPHeader2,
AddressInfo, tcpdump(1) */

class IP6Filter : public Element { 
public:
    IP6Filter() CLICK_COLD;
    ~IP6Filter() CLICK_COLD;

    const char *class_name() const		{ return "IP6Filter"; }
    const char *port_count() const		{ return "1/-"; }
    const char *processing() const		{ return PUSH; }
    // this element does not need AlignmentInfo; override Classifier's "A" flag
    const char *flags() const			{ return ""; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    
    void push(int port, Packet *);

private:
    Vector<ip6filtering::AST> ast_list; // a list of ASTs (abstract syntax trees)

};

CLICK_ENDDECLS
#endif /* IP6Filter */

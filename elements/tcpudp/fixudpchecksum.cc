/*
 * fixudpchecksum.{cc,hh} -- element fixes UDP checksum for IPv6 packets
 * Glenn Minne
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2007 Regents of the University of California
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "fixudpchecksum.hh"
#include <click/ip6address.hh>
CLICK_DECLS

FixUDPChecksum::FixUDPChecksum()
{
}

FixUDPChecksum::~FixUDPChecksum()
{
}

int
FixUDPChecksum::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return 0;
}

Packet *
FixUDPChecksum::simple_action(Packet *p)
{
    click_udp *udp = (click_udp*) p->transport_header();
    click_ip6 *ip6 = (click_ip6*) p->network_header();

    //TO DO: ADD SUPPORT FOR CORRECT CHECKSUM IN CASE OF ROUTING HEADER    
    udp->uh_sum = htons(in6_fast_cksum(&ip6->ip6_src, &ip6->ip6_dst, udp->uh_ulen, ip6->ip6_nxt, udp->uh_sum, (unsigned char *)(udp), udp->uh_ulen)); //reuse the icmp6 checksum calculation from ip6ndsolicitor.cc, because ICMPv6 uses the same checksum as UDP over IPv6 (see RFC 2460, 8.1)

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(FixUDPChecksum)
ELEMENT_MT_SAFE(FixUDPChecksum)

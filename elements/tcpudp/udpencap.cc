/*
 * udpencap.{cc,hh} -- element encapsulates packet in UDP/IP header
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
#include "udpencap.hh"
#include <click/args.hh>
#include <click/glue.hh>
CLICK_DECLS

UDPEncap::UDPEncap()
{
}

UDPEncap::~UDPEncap()
{
}

int
UDPEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
    uint16_t sport, dport;

    if (Args(conf, this, errh)
	.read_mp("SPORT", IPPortArg(IP_PROTO_UDP), sport)
	.read_mp("DPORT", IPPortArg(IP_PROTO_UDP), dport)
	.complete() < 0)
    return -1;

    _sport = htons(sport);
    _dport = htons(dport);
    
    return 0;
}

Packet *
UDPEncap::simple_action(Packet *p_in)
{
    WritablePacket *p = p_in->push(sizeof(click_udp));
    click_udp *udp = reinterpret_cast<click_udp *>(p->data());

    // set up UDP header
    udp->uh_sport = _sport;
    udp->uh_dport = _dport;
    uint16_t len = p->length();
    udp->uh_ulen = htons(len);
    udp->uh_sum = 0;

    return p;
}

String UDPEncap::read_handler(Element *e, void *thunk)
{
    UDPEncap *u = static_cast<UDPEncap *>(e);
    switch ((uintptr_t) thunk) {
    case 0:
	    return String(ntohs(u->_sport));
    case 1:
	    return String(ntohs(u->_dport));
    default:
	    return String();
    }
}

void UDPEncap::add_handlers()
{
    add_read_handler("sport", read_handler, 0);
    add_write_handler("sport", reconfigure_keyword_handler, "0 SPORT");
    add_read_handler("dport", read_handler, 1);
    add_write_handler("dport", reconfigure_keyword_handler, "1 DPORT");
}

CLICK_ENDDECLS
EXPORT_ELEMENT(UDPEncap)
ELEMENT_MT_SAFE(UDPEncap)

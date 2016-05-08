/*
 * hopbyhopencap.{cc,hh} -- encapsulates packet in a Hop-by-Hop IPv6 extension header
 * Glenn Minne
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
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
#include "hopbyhopencap.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip6.h>
CLICK_DECLS

HopByHopEncap::HopByHopEncap()
{
}

HopByHopEncap::~HopByHopEncap()
{
}

int
HopByHopEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
    _header_ext_length = 0;
    
    if (Args(conf, this, errh)
	.read_mp("PROTO", IntArg(), _next_header)
	.read_p("LEN", IntArg(), _header_ext_length)
	.complete() < 0)
	    return -1;    
    
    return 0;
}

Packet *
HopByHopEncap::simple_action(Packet *p_in)
{
    WritablePacket *p = p_in->push(sizeof(click_ip6_hbh) + (_header_ext_length * 8));  // _header_ext_length gives the size in 64-bit/8-octet units/8 byte units.
    click_ip6_hbh *hbh = reinterpret_cast<click_ip6_hbh *>(p->data());
    hbh->ip6h_nxt = _next_header;
    hbh->ip6h_len = _header_ext_length;
    
    uint16_t *options_and_padding = (uint16_t*) hbh++;
    *options_and_padding = 0;
    options_and_padding++;
    *options_and_padding = 0;
    options_and_padding++;
    *options_and_padding = 0;
    
    if (_header_ext_length > 0) {
        uint64_t *options_and_padding = (uint64_t*) options_and_padding++;
        for (int i = 0; i < _header_ext_length; i++) {
            *options_and_padding = 0;
            options_and_padding++;
        }
    }
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HopByHopEncap)

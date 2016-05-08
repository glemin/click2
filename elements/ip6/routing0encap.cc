/*
 * routing0encap.{cc,hh} -- encapsulates packet in a Routing0 extension header
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
#include "routing0encap.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip6.h>

#include <click/string.hh>
CLICK_DECLS

RoutingZeroEncap::RoutingZeroEncap()
{
}

RoutingZeroEncap::~RoutingZeroEncap()
{
}

int
RoutingZeroEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{   
    String unparsed_addresses;
    
    if (Args(conf, this, errh)
	.read_mp("PROTO", IntArg(), _next_header)
	.read_mp("ADDRESSES", unparsed_addresses)
	.complete() < 0)
	    return -1;
	    
	String current_word = "";
	IP6Address address;
	for (int i = 0; i < unparsed_addresses.length(); i++) {
	    if (isspace(unparsed_addresses[i])) {               // if we get a space, please evaluate
	        // try to parse the word and add to list
            if (IP6AddressArg().parse(current_word, address)) {
                _ip6_addresses.push_back(*(in6_addr*) address.data());
                current_word = "";  // reset the current word
            } else {
                return errh->error("The address '%s' is not a valid IPv6 address", current_word.c_str());
            }
	    } else if (i == unparsed_addresses.length()-1) {     // if we arrived at the end of the string, please evaluate, but also read the last symbol
	        // add character to current word
	        current_word += unparsed_addresses[i];
	        
            // try to parse the word and add to list
            if (IP6AddressArg().parse(current_word, address)) {
                _ip6_addresses.push_back(*(in6_addr*) address.data());
                current_word = "";  // reset the current word
            } else {
                return errh->error("The address '%s' is not a valid IPv6 address", current_word.c_str());
            }
	    } else {
	        // add character to current word
	        current_word += unparsed_addresses[i];
	    }
	}
	 _header_ext_length = 2 * _ip6_addresses.size(); /* RFC 2460 states that the header extension length is 2 times the number of addresses in a Routing 0 header */
	 _segments_left = _ip6_addresses.size(); /* the number of still to be visited nodes is equal to all given ip6 addresses because none of them has been visited yet at the point
	                                           of packet creation */
    return 0;
}

Packet *
RoutingZeroEncap::simple_action(Packet *p_in)
{
    WritablePacket *p = p_in->push(sizeof(click_ip6_rthdr0) + (_ip6_addresses.size() * sizeof(in6_addr))); // make room for the new Routing0 extension header

    if (!p)
        return 0;

    click_ip6_rthdr0 *routing0_extension_header = reinterpret_cast<click_ip6_rthdr0 *>(p->data());

    // set the values of the Routing0 extension header
    routing0_extension_header->ip6r0_nxt = _next_header;
    routing0_extension_header->ip6r0_len = _header_ext_length;
    routing0_extension_header->ip6r0_type = 0;
    routing0_extension_header->ip6r0_segleft = _segments_left;
    routing0_extension_header->ip6r0_reserved = 0;
    
    in6_addr* ip6_address = (in6_addr*) (routing0_extension_header + 1);
    
    for (int i = 0; i < _ip6_addresses.size(); i++) {
        *ip6_address = _ip6_addresses[i];
        ip6_address++;
    }

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RoutingZeroEncap)

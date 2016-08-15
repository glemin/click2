/*
 * storeip6address.{cc,hh} -- element stores IPv6 destination annotation into
 * packet
 * Glenn Minne
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
 *
 * For using the 'src' and 'dst argument the IPv6 header pointers MUST be set.
 */

#include <click/config.h>
#include "storeip6address.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip6.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
CLICK_DECLS

StoreIP6Address::StoreIP6Address()
{
}

StoreIP6Address::~StoreIP6Address()
{
}

int
StoreIP6Address::configure(Vector<String> &conf, ErrorHandler *errh)
{

    String offset;	// the offset to be read; can be equal to src or dst in stead of a number, in which case this has a special meaning.
    int r;		// reply

    if (conf.size() == 1) {
	      r = Args(conf, this, errh).read_mp("OFFSET", WordArg(), offset).complete();
        _address_given = false;
    } else if (conf.size() == 2) {
	      r = Args(conf, this, errh).read_mp("ADDR", _address).read_mp("OFFSET", WordArg(), offset).complete();
        _address_given = true;
    } else { // conf size should be 1 or 2
        return -1;
    }

    if (r < 0) { // a parse error occured, we should stop and return an error.
        return r;
    }

    /* translate src and dst into their actual number counterparts */
    if (offset.lower() == "src") {
        _offset = 8;
    } else if (offset.lower() == "dst") {
        _offset = 24;
    } else { // normal parsing needs to be done
         bool parseErrors = IntArg().parse(offset, _offset); //parse offset and place it in _offset
         if (!parseErrors || _offset < 0) {
             return -1;
         }
    }
    return 0;
}

Packet *
StoreIP6Address::simple_action(Packet *p)
{
    if (!_address_given) {		// if no address was explicitely given, we need to read it in via p->dst_ip6_anno()
        _address = DST_IP6_ANNO(p);
	  }

    memcpy(((uint8_t*) p->network_header_offset()) + _offset, &_address, 16);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StoreIP6Address)
ELEMENT_MT_SAFE(StoreIP6Address)

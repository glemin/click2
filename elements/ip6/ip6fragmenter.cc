/*
 * ip6fragmenter.{cc,hh} -- element fragments IP6 packets
 * Glenn Minne
 *
 * Copyright (c) 1999 Massachusetts Institute of Technology
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
#include "ip6fragmenter.hh"
#include <clicknet/ip6.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <clicknet/ether.h>
#include <fstream>
CLICK_DECLS

IP6Fragmenter::IP6Fragmenter()
{
  _MTU = 0;
  _id = 0;
}

IP6Fragmenter::~IP6Fragmenter()
{
}

int
IP6Fragmenter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int return_type = Args(conf, this, errh).read_mp("MTU", _MTU).complete();
    if (return_type == 0) {
        if (_MTU > 4960) {
            return errh->error("The maximum packet size is 4960");
        } else {
            return 0;
        }
    } else {
        return return_type;
    }
}

//  If the original packet was too big to reach the final destination then
//  this element splits the original packet, which could look like this:
//
//   +------------------+--------------+--------------+--//--+----------+
//   |  Unfragmentable  |    first     |    second    |      |   last   |
//   |       Part       |   fragment   |   fragment   | .... | fragment |
//   +------------------+--------------+--------------+--//--+----------+
//
//   up into multiple fragment packets which can look like this:
//
//   +------------------+--------+--------------+
//   |  Unfragmentable  |Fragment|    first     |
//   |       Part       | Header |   fragment   |
//   +------------------+--------+--------------+
//
//   +------------------+--------+--------------+
//   |  Unfragmentable  |Fragment|    second    |
//   |       Part       | Header |   fragment   |
//   +------------------+--------+--------------+
//                         o
//                         o
//                         o
//   +------------------+--------+----------+
//   |  Unfragmentable  |Fragment|   last   |
//   |       Part       | Header | fragment |
//   +------------------+--------+----------+
//

// The unfragmentable part is as you can see transmitted with every fragmented packet.
// This unfragmentable part has the IPv6 header (40 bytes long) and certain types IPv6 
// extension headers.

// The fragments have the remaining IPv6 extension headers, higher layer protocol headers,
// and payload.
void
IP6Fragmenter::push(int, Packet *p)
{
    if (p->length() <= _MTU) {
        output(0).push(p);
    } else {
        // Fragmentable part
        uint8_t* fragmentable_part_ptr = (uint8_t*) p->data() + _unfragmentable_part_length;
        uint32_t fragmentable_part_length = p->length() - _unfragmentable_part_length;      // size of big payload to be distributed over small fragments
        uint32_t non_last_fragment_length = _MTU - _unfragmentable_part_length - sizeof(click_ip6_fragment);
        non_last_fragment_length  -= (_MTU - _unfragmentable_part_length - sizeof(click_ip6_fragment)) % 8; // round down to multiple of 8 bytes
        ((click_ip6*) p->data())->ip6_plen = htons((_unfragmentable_part_length - 40) + sizeof(click_ip6_fragment) + non_last_fragment_length);
        
        uint32_t remainder = fragmentable_part_length % non_last_fragment_length;
        // === SENDING PACKETS ===
        // Packets that have a size that is a multiple of 8 bytes
        for (unsigned i = 1; i <= (fragmentable_part_length / non_last_fragment_length); i++) {
            WritablePacket *packet = Packet::make(0, _unfragmentable_part_length + sizeof(click_ip6_fragment) + non_last_fragment_length);
            
            // Add unfragmentable part
            memcpy((void*) packet->data(), p->data(), _unfragmentable_part_length);
       
            // Add fragment header
            click_ip6_fragment* ip6_frag_header = (click_ip6_fragment*) ((uint8_t*) packet->data() + _unfragmentable_part_length);
            ip6_frag_header->ip6_frag_nxt = _next; // The Next Header value that identifies the first header of the Fragmentable Part of the original packet.
            if ((i == fragmentable_part_length / non_last_fragment_length) && (remainder == 0)) {  
                // special case with no remainder
                // although it says it is a non_last_fragment it is the last fragment or packet
                // because of this it must have a zero in the last position indicating 'no more fragments follow'
                ip6_frag_header->ip6_frag_offset = htons(((((i-1) * (non_last_fragment_length/8)) << 3) & 0b1111111111111000));
            } else {
                ip6_frag_header->ip6_frag_offset = htons(((((i-1) * (non_last_fragment_length/8)) << 3) & 0b1111111111111000) | 0b0000000000000001);
            }
            ip6_frag_header->ip6_frag_id = _id;
            
            // Add 'i'-th fragment
            memcpy(ip6_frag_header + 1, fragmentable_part_ptr + ((i-1) * (non_last_fragment_length)), non_last_fragment_length);
            
            output(0).push(packet);
        }
        // Possibly the last packet that might not be a multiple of 8 bytes
        if (remainder != 0) {
            WritablePacket *packet = Packet::make(0, _unfragmentable_part_length + sizeof(click_ip6_fragment) + remainder);
            
            // Adapt length in original packet header
            ((click_ip6*) p->data())->ip6_plen = htons((_unfragmentable_part_length - 40) + sizeof(click_ip6_fragment) + remainder);
            
            // Add unfragmentable part
            memcpy((void*) packet->data(), p->data(), _unfragmentable_part_length);
            
            // Add fragment header
            click_ip6_fragment* ip6_frag_header = (click_ip6_fragment*) ((uint8_t*) packet->data() + _unfragmentable_part_length);
            ip6_frag_header->ip6_frag_nxt = _next; // The Next Header value that identifies the first header of the Fragmentable Part of the original packet.
            ip6_frag_header->ip6_frag_offset = htons(((((fragmentable_part_length / (non_last_fragment_length + sizeof(click_ip6_fragment))) * (non_last_fragment_length/8)) << 3) & 0b1111111111111000));
            ip6_frag_header->ip6_frag_id = _id;
            
            // Add last fragment
            memcpy(ip6_frag_header + 1, fragmentable_part_ptr + ((fragmentable_part_length / (non_last_fragment_length + sizeof(click_ip6_fragment))) * (non_last_fragment_length)), remainder);
            
            output(0).push(packet);            
        }
        
        _id ++;
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Fragmenter)

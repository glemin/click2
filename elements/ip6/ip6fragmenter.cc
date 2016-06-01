/*
 * ip6fragmenter.{cc,hh} -- element fragments IP6 packets
 * Robert Morris
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
CLICK_DECLS

IP6Fragmenter::IP6Fragmenter()
  : _drops(0)
{
  _fragments = 0;
  _MTU = 0;
}

IP6Fragmenter::~IP6Fragmenter()
{
}


int
IP6Fragmenter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int return_value = Args(conf, this, errh).read_mp("MTU", _MTU).complete();
    // Determine the fragmentation size now in bytes.
    // This fragmentation size must be a multiple of 8 bytes according to the RFC.
    
    if ((_MTU / 8) != 0) {
        _fragment_size = _MTU - (_MTU / 8);     // The size we say an individual fragment will have,
                                                // it is the nearest multiple of 8 of the MTU lower than the MTU
    }
    
    click_chatter("de return value is %i", return_value);
}

 /*
int
IP6Fragmenter::optcopy(click_ip6 *ip1, click_ip6 *ip2)
{
  int opts = (ip1->ip_hl << 2) - sizeof(click_ip6);
  u_char *base1 = (u_char *) (ip1 + 1);
  int i1, optlen;
  int i2 = 0;
  u_char *base2 = (u_char *) (ip2 + 1);

  for(i1 = 0; i1 < opts; i1 += optlen){
    int opt = base1[i1];
    if(opt == IPOPT_EOL)
      break;
    if(opt == IPOPT_NOP){
      optlen = 1;
    } else {
      optlen = base1[i1+1];
    }

    if(opt & 0x80){
    // copy it
      if(ip2){
        memcpy(base2 + i2, base1 + i1, optlen);
      }
      i2 += optlen;
    }
  }

  for( ; i2 & 3; i2++)
    if(ip2)
      base2[i2] = IPOPT_EOL;

  return(i2);
}

*/
void
IP6Fragmenter::fragment(Packet *)
{ }

/*
inline Packet *
IP6Fragmenter::smaction(Packet *p)
{
  if (p->length() <= _mtu)
    {
      //click_chatter("IP6Fragmenter: length is OK, <= %x \n", _mtu);
      return(p);
    }
  else
    {
      click_chatter("IP6Fragmenter: length is not OK, > %x \n", _mtu);
      if (noutputs() == 2)
	output(1).push(p);
      else
	p->kill();
      return 0;
    }
}
*/

static String
IP6Fragmenter_read_drops(Element *xf, void *)
{
  IP6Fragmenter *f = (IP6Fragmenter *)xf;
  return String(f->drops());
}

static String
IP6Fragmenter_read_fragments(Element *xf, void *)
{
  IP6Fragmenter *f = (IP6Fragmenter *)xf;
  return String(f->fragments());
}

void
IP6Fragmenter::add_handlers()
{
  add_read_handler("drops", IP6Fragmenter_read_drops, 0);
  add_read_handler("fragments", IP6Fragmenter_read_fragments, 0);
}

uint32_t
IP6Fragmenter::size_of_IPv6_part(click_ip6* p) {
    uint32_t size_of_IPv6_part = 40;    // size of the standard IPv6 part
    uint8_t nxt = p->ip6_nxt;
    while (nxt == 0 || nxt == 43 || nxt == 60) {
	    if (nxt == 43) {
	        nxt = ((click_ip6_rthdr *) p)->ip6r_nxt;
	        // move the packet pointer
	        p = (click_ip6*) ((click_ip6_rthdr *) p + (uint32_t) (((click_ip6_rthdr *) p)->ip6r_len));
	        
	        size_of_IPv6_part += ((click_ip6_rthdr *) p)->ip6r_len;   // increase the total size of the IPv6 part
	    } else if (nxt == 60) {
	        nxt = ((click_ip6_dest *) p)->ip6d_nxt;
	        // move the packet pointer
	        p = (click_ip6*) ((click_ip6_dest *) p + (uint32_t) (((click_ip6_dest *) p)->ip6d_len));
	        
	        size_of_IPv6_part += ((click_ip6_dest *) p)->ip6d_len;   // increase the total size of the IPv6 part
	    } else if (nxt == 0) {
            nxt = ((click_ip6_hbh *) p)->ip6h_nxt;
	        // move the packet pointer
	        p = (click_ip6*) ((click_ip6_hbh *) p + (uint32_t) (((click_ip6_hbh *) p)->ip6h_len));
	        
	        size_of_IPv6_part += ((click_ip6_hbh *) p)->ip6h_len;   // increase the total size of the IPv6 part
	    } else {
	        break;  // quit the while loop
	    }
    }
    return size_of_IPv6_part;
}

void
IP6Fragmenter::push(int, Packet *p)
{
  // click_chatter("IP6Fragmenter::push, packet length is %x \n", p->length());
    click_ip6 original_packets_ipv6_header = *(click_ip6*)p;
    original_packets_ipv6_header.ip6_nxt = 44;  // fragmentation header

    if (p->length() <= _MTU) {
        // click_chatter("**********************1");
        output(0).push(p);
    } else {
        uint32_t length_of_IPv6_protocol = size_of_IPv6_part((click_ip6*) p);   // How long is the IPv6 part (standard header +
                                                                                // extension headers).
        for (int i = 1; i <= p->length() / (_fragment_size - length_of_IPv6_protocol); i++) {
    	    click_ip6 *packet = (click_ip6*) Packet::make(0, _fragment_size);
    	    *packet = original_packets_ipv6_header;
    	    ((click_ip6_fragment*) (packet+1))->ip6_frag_nxt = 44;  // Fragmentation Header
    	    ((click_ip6_fragment*) (packet+1))->ip6_frag_reserved = 0;
    	    ((click_ip6_fragment*) (packet+1))->ip6_frag_offset = (i-1) * _fragment_size;
            if (i != p->length() / (_MTU - length_of_IPv6_protocol)) {
                // more fragments 0
        	    ((click_ip6_fragment*) (packet+1))->ip6_frag_offset = (i-1) * _fragment_size;
    	    //    ((click_ip6_fragment*) (packet+1))->ip6_frag_nxt = 44;  // Fragmentation Header
            } else {
                // more fragments 1
        	    ((click_ip6_fragment*) (packet+1))->ip6_frag_offset = (i-1) * _fragment_size;
            //    ip6_frag_id
            }
        }

        click_chatter("%u", size);
        click_chatter("done");
      // click_chatter("**********************2");
      // output(0).push(p);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Fragmenter)

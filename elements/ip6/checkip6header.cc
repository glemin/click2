/*
 * checkip6header.{cc,hh} -- element checks IP6 header for correctness
 * (lengths, source addresses)
 * Robert Morris , Peilei Fan
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
#include "checkip6header.hh"
#include <clicknet/ip6.h>
#include <clicknet/icmp6.h>
#include <click/ip6address.hh>
#include <click/glue.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/standard/alignmentinfo.hh>
CLICK_DECLS

CheckIP6Header::CheckIP6Header()
  : _bad_src(0), _drops(0)
{
}

CheckIP6Header::~CheckIP6Header()
{
  delete[] _bad_src;
}

int
CheckIP6Header::configure(Vector<String> &conf, ErrorHandler *errh)
{
 String badaddrs = String::make_empty();
 _offset = 0;
 Vector<String> ips;
 // ips.push_back("0::0"); // this address is only bad if we are a router
 ips.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // bad IP6 address

 if (Args(conf, this, errh)
     .read_p("BADADDRS", badaddrs)
     .read_p("OFFSET", _offset)
     .complete() < 0)
    return -1;

  if (badaddrs) {
    Vector<String> words;
    cp_spacevec(badaddrs, words);
    IP6Address a;
    for (int j = 0; j < words.size(); j++) {
      if (!cp_ip6_address(words[j], (unsigned char *)&a)) {
        return errh->error("expects IP6ADDRESS -a ");
      }
      for (int j = 0; j < ips.size(); j++) {
	    IP6Address b = IP6Address(ips[j]);
	    if (b == a)
	      goto repeat;
      }
      ips.push_back(a.s());
      repeat: ;
    }
  }

  _n_bad_src = ips.size();
  _bad_src = new IP6Address [_n_bad_src];

  for (int i = 0; i<_n_bad_src; i++) {
    _bad_src[i]= IP6Address(ips[i]);
  }

  return 0;
}

void
CheckIP6Header::drop_it(Packet *p)
{
  if (_drops == 0)
    click_chatter("IP6 header check failed");
  _drops++;
  
  if (noutputs() == 2) {
    output(1).push(p);
  }else  {
    p->kill();
  }
}

Packet *
CheckIP6Header::simple_action(Packet *p)
{
  const click_ip6 *ip = reinterpret_cast <const click_ip6 *>( p->data() + _offset);
  unsigned plen = p->length() - _offset;
  unsigned remaining_packet_length = p->length() - _offset;
  class IP6Address src;

  // check if the packet is smaller than ip6 header
  // cast to int so very large plen is interpreted as negative
  if((int)plen < (int)sizeof(click_ip6))
    goto bad;
    
    
   // check if the PayloadLength field is valid
   if(ntohs(ip->ip6_plen) > (plen-40))
     goto bad;

  // check version
  if(ip->ip6_v != 6)
    goto bad;



  /*
   * discard illegal source addresses.
   * Configuration string should have listed all subnet
   * broadcast addresses known to this router.
   */
   src=ip->ip6_src;
   for(int i = 0; i < _n_bad_src; i++) {
     if(src == _bad_src[i])
       goto bad;
   }

  /*
   * discard illegal destinations.
   * We will do this in the IP6 routing table.
   *
   *
   */

  try {
  /*
   * discard packets that have wrongly formed extension headers & send an icmp error
   */
   if (ip->ip6_nxt == 0) { // Hop-by-Hop Options
     this->check_hbh((click_ip6_hbh*) (ip++), remaining_packet_length-40);
   } else if (ip->ip6_nxt == 60) { // Destination Options
     this->check_dest((click_ip6_dest*) (ip++), remaining_packet_length-40);
   } else if (ip->ip6_nxt == 43) { // Routing
     this->check_rthdr((click_ip6_rthdr*) (ip++), remaining_packet_length-40);
   } else if (ip->ip6_nxt == 44) { // Fragmentation
     this->check_fragment((click_ip6_fragment*) (ip++), remaining_packet_length-40);
   }
   
   } catch (bool success) {
     if (success == false) {
       goto bad; // bad drops the original packet
     }
   } catch (Packet *error_packet) {
     output(1).push(p); // we came across an error that also outputs an icmpv6 error message
     goto bad; // bad drops the original packet
   }

  
  p->set_ip6_header(ip);

  output(0).push(p);
  return 0;

 bad:
  drop_it(p);
  return 0;
  
}


void
CheckIP6Header::check_hbh(click_ip6_hbh *hbh_header, unsigned remaining_packet_length) {
  if (remaining_packet_length >= sizeof(click_ip6_hbh)) {   // contains at least the Hop-by-Hop Options standard header
    if (hbh_header->ip6h_nxt == 60) { // Destination Options
      this->check_dest((click_ip6_dest*) ((uint8_t*) hbh_header + (8 * hbh_header->ip6h_len) + 8), remaining_packet_length - (8 * hbh_header->ip6h_len + 8));
    } else if (hbh_header->ip6h_nxt == 43) { // Routing
      this->check_rthdr((click_ip6_rthdr*) ((uint8_t*) hbh_header + (8 * hbh_header->ip6h_len) + 8), remaining_packet_length - (8 * hbh_header->ip6h_len + 8));
    } else if (hbh_header->ip6h_nxt == 44) { // Fragmentation
      this->check_fragment((click_ip6_fragment*) ((uint8_t*) hbh_header + (8 * hbh_header->ip6h_len) + 8), remaining_packet_length - (8 * hbh_header->ip6h_len + 8));
    } else if (hbh_header->ip6h_nxt == 0) { // Error, Hop-By-Hop Options headers should not occur after a Hop-by-Hop Options header
      throw generate_icmp6_parameter_problem(0);    // TODO fill in the offset value
    } else if (hbh_header->ip6h_nxt == 51 || hbh_header->ip6h_nxt == 50 || hbh_header->ip6h_nxt == 135) { // Error, Authentication Header, Encapsulation Security Payload and Mobility respectively are not supported yet
 //     throw create_parameter_unknown_problem(0);
    } else {
      if ((remaining_packet_length >= (8 * (unsigned) hbh_header->ip6h_len + 8))) { // contains enough free space for the Hob-by-Hop Options options portion   
        // all tests passed, no errors found
      } else {
        throw false;
      }
    }
  }
  throw false;
}

void
CheckIP6Header::check_dest(click_ip6_dest *dest_header, unsigned remaining_packet_length) {
  if (remaining_packet_length >= sizeof(click_ip6_dest)) {   // contains at least the Destination Options standard header
    if (dest_header->ip6d_nxt == 43) { // Routing
      this->check_rthdr((click_ip6_rthdr*) ((uint8_t*) dest_header + (8 * dest_header->ip6d_len) + 8), remaining_packet_length - (8 * dest_header->ip6d_len + 8));
    } else if (dest_header->ip6d_nxt == 44) { // Fragmentation
      this->check_fragment((click_ip6_fragment*) ((uint8_t*) dest_header + (8 * dest_header->ip6d_len) + 8), remaining_packet_length - (8 * dest_header->ip6d_len + 8));
    } else if (dest_header->ip6d_nxt == 0) { // Error, Hop-By-Hop Options headers should not occur after a Destination Options header
      throw generate_icmp6_parameter_problem(0);
    } else if (dest_header->ip6d_nxt == 51 || dest_header->ip6d_nxt == 50 || dest_header->ip6d_nxt == 135) { // Error, Authentication Header, Encapsulation Security Payload and Mobility respectively are not supported yet
 //     throw create_parameter_unknown_problem(0);      
    } else {
      if (remaining_packet_length >= (8 * (unsigned) dest_header->ip6d_len + 8)) { // contains enough free space for the Destion Options options portion 
        
      } else {
        throw false;
      }
    }
  }
  throw false;
}

void
CheckIP6Header::check_rthdr(click_ip6_rthdr *rthdr_header, unsigned remaining_packet_length) {
  if (remaining_packet_length >= sizeof(click_ip6_rthdr)) {   // contains at least the Routing standard header
    if (rthdr_header->ip6r_nxt == 60) { // Destination Options
      this->check_dest((click_ip6_dest*) ((uint8_t*) rthdr_header + (8 * rthdr_header->ip6r_len) + 8), remaining_packet_length - (8 * rthdr_header->ip6r_len + 8));
    } else if (rthdr_header->ip6r_nxt == 44) { // Fragmentation
      this->check_fragment((click_ip6_fragment*) ((uint8_t*) rthdr_header + (8 * rthdr_header->ip6r_len) + 8), remaining_packet_length - (8 * rthdr_header->ip6r_len + 8));
    } else if (rthdr_header->ip6r_nxt == 0) { // Error, Hop-By-Hop Options headers should not occur after a Routing header
      throw generate_icmp6_parameter_problem(0);
    } else if (rthdr_header->ip6r_nxt == 51 || rthdr_header->ip6r_nxt == 50 || rthdr_header->ip6r_nxt == 135) { // Error, Authentication Header, Encapsulation Security Payload and Mobility respectively are not supported yet
 //     throw create_parameter_unknown_problem(0);      
    } else {
       if (remaining_packet_length >= (8 * (unsigned) rthdr_header->ip6r_len + 8)) { // contains enough free space for the Routing options portion
         
       } else {
         throw false;
       }
    }
  }
  throw false;
}

void
CheckIP6Header::check_fragment(click_ip6_fragment *fragment_header, unsigned remaining_packet_length) {
  if (remaining_packet_length >= sizeof(click_ip6_fragment)) {   // contains the Fragment header
    if (fragment_header->ip6_frag_nxt == 60) { // Destination Options
      this->check_dest((click_ip6_dest*) (fragment_header++), remaining_packet_length - sizeof(click_ip6_fragment));
    } else if (fragment_header->ip6_frag_nxt == 43) { // Routing
      this->check_rthdr((click_ip6_rthdr*) (fragment_header++), remaining_packet_length - sizeof(click_ip6_fragment));
    } else if (fragment_header->ip6_frag_nxt == 0) { // Error, Hop-By-Hop Options headers should not occur after a Fragment header
      throw generate_icmp6_parameter_problem(0);
    } else if (fragment_header->ip6_frag_nxt == 51 || fragment_header->ip6_frag_nxt == 50 || fragment_header->ip6_frag_nxt == 135) { // Error, Authentication Header, Encapsulation Security Payload and Mobility respectively are not supported yet
//      throw create_parameter_unknown_problem(0);
    } else {
      // all tests passed
    }
  }
  throw false;
}

static String
CheckIP6Header_read_drops(Element *xf, void *)
{
  CheckIP6Header *f = (CheckIP6Header *)xf;
  return String(f->drops());
}

void
CheckIP6Header::add_handlers()
{
  add_read_handler("drops", CheckIP6Header_read_drops);
}

/* private functions */
inline Packet*
CheckIP6Header::generate_icmp6_parameter_problem(unsigned offset) {
  return 0;   // TODO implement this
}



Packet*
CheckIP6Header::create_parameter_problem_message(uint8_t* packet_content, uint8_t* packet_content_end, uint8_t code, uint32_t pointer) {
  unsigned const packet_length = packet_content_end - packet_content;
  click_ip6* ip6_header_erroneous_packet = (click_ip6*) packet_content;
  
  WritablePacket *q = 0;

  if (packet_length >= 1232) {
    q = Packet::make(1280);
    if (!q) {
      q->kill();
      return 0;
    }
    click_ip6* ip6_header = (click_ip6*) q;
    ip6_header->ip6_v = 6;
    ip6_header->ip6_flow = 0;
    ip6_header->ip6_plen = 1240;
    ip6_header->ip6_nxt = 58;
    ip6_header->ip6_hlim = 255;
    ip6_header->ip6_src = ip6_header_erroneous_packet->ip6_dst;
    ip6_header->ip6_dst = ip6_header_erroneous_packet->ip6_src;
    click_icmp6_paramprob* icmp6_paramprob_header = (click_icmp6_paramprob*) (ip6_header + 1);
    icmp6_paramprob_header->icmp6_type = 4;  // ICMP6_PARAMPROB
    icmp6_paramprob_header->icmp6_code = code;
    icmp6_paramprob_header->icmp6_cksum = 0;
    icmp6_paramprob_header->icmp6_pointer = pointer;
    uint8_t* data = (uint8_t*) (icmp6_paramprob_header + 1);
    memcpy(data,packet_content,1232);
  } else {
    q = Packet::make(packet_length + 48); // 48 = sizeof(click_ip6) + sizeof(click_icmp6_paramprob)
    if (!q) {
      q->kill();
      return 0;
    }    
    click_ip6* ip6_header = (click_ip6*) q;
    ip6_header->ip6_v = 6;
    ip6_header->ip6_flow = 0;
    ip6_header->ip6_plen = 1240;
    ip6_header->ip6_nxt = 58;
    ip6_header->ip6_hlim = 255;
    ip6_header->ip6_src = ip6_header_erroneous_packet->ip6_dst;
    ip6_header->ip6_dst = ip6_header_erroneous_packet->ip6_src;
    click_icmp6_paramprob* icmp6_paramprob_header = (click_icmp6_paramprob*) (ip6_header + 1);
    icmp6_paramprob_header->icmp6_type = 4;  // ICMP6_PARAMPROB
    icmp6_paramprob_header->icmp6_code = code;
    icmp6_paramprob_header->icmp6_cksum = 0;
    icmp6_paramprob_header->icmp6_pointer = pointer;
    uint8_t* data = (uint8_t*) (icmp6_paramprob_header + 1);
    memcpy(data,packet_content,packet_length);    
  }
  return q;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CheckIP6Header)

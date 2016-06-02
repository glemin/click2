/*
 * ip6fragmenter.{cc,hh} -- element fragments IP6 packets
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
    int return_type = Args(conf, this, errh).read_mp("MTU", _MTU).complete();
    if (return_type == 0) {
        if (_MTU <= 4960) {
            return 0;
        } else {
            return errh->error("The maximum packet size is 4960");
        }
    } else {
        return return_type;
    }
    
/*    // Determine the fragmentation size now in bytes.
    // This fragmentation size must be a multiple of 8 bytes according to the RFC.
    if (return_value == 0) {
        _fragment_size = _MTU - (_MTU % 8);     // The size we say an individual fragment will have,
                                                      // it is the nearest multiple of 8 of the MTU lower than the MTU.
                                                      // In the special case of it being a multiple of 8 _fragment_size = _MTU - 0, or just the _MTU.
                                                      // This size contains both the IPv6 headers and the size of the payload
        return 0;
    } else {
        return return_value;                          // A parse error occured
    }
*/

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

// Updates the nxt field of the last IPv6 Header so it indicates 44 (= fragmentation header)
// Returns the size of the IPv6 part as well as the last "nxt value" of the last IPv6 header
// in the chain. This "nxt value" will be the value used in the IPv6 Extension Header.
uint32_t
IP6Fragmenter::size_of_IPv6_part_and_update_chain(click_ip6* p, uint8_t& nxt) {
    p->ip6_nxt = 44;    // TODO Check in Wireshark
    uint32_t size_of_IPv6_part = 40;    // size of the standard IPv6 part
    nxt = p->ip6_nxt;
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
//    ((click_ip6_hbh*) p)->ip6h_nxt = 44;      // fragmentation header
    
    return size_of_IPv6_part;
}

void
IP6Fragmenter::push(int, Packet *p)
{
    if (p->length() <= _MTU) {
        // click_chatter("**********************1");
        output(0).push(p);
    } else {
        uint8_t nxt;
        
        uint32_t size_of_IPv6_headers = size_of_IPv6_part_and_update_chain((click_ip6*) p, nxt);// How long is the IPv6 part (standard header +
                                                                                     // extension headers).
                                                                                     // Also updates the IPv6 part so the nxt header fields
                                                                                     // are renewed.
                                                                                     // nxt is a value later used to indicate which
                                                                                     // non-IPv6 protocol follows the IPv6 protocol chain.

        uint32_t size_of_data_part = _MTU - size_of_IPv6_headers - sizeof(click_ip6_fragment);
        size_of_data_part -= (_MTU - size_of_IPv6_headers - sizeof(click_ip6_fragment)) % 8;    // subtract the remainder to make it a multiple of 8 bytes
        

        click_ip6* packet2 = (click_ip6*) p->data();
        packet2->ip6_plen = htons(size_of_data_part + sizeof(click_ip6_fragment));         // Adjust the packet payload
        
        void* IPv6_headers_copy = malloc(size_of_IPv6_headers);
        click_chatter("size_of_IPv6_headers = %u", size_of_IPv6_headers);
        memcpy(IPv6_headers_copy, p->data(), size_of_IPv6_headers);                 // Adjusted IPv6 header is copied
        
        uint8_t* IPv6_payload = (uint8_t*) p->data() + size_of_IPv6_headers;
        


        
        uint32_t size_of_big_payload = p->length() - size_of_IPv6_headers;      // size of big payload to be distributed over small fragments
        
        for (int i = 1; i <= (size_of_big_payload / size_of_data_part) + 1; i++) {
            WritablePacket *packet = Packet::make(0, size_of_data_part + sizeof(click_ip6_fragment) + size_of_IPv6_headers);
            
            // add IPv6 headers
            void* ip6_packet = (void*) packet->data();
            memcpy(ip6_packet, IPv6_headers_copy, size_of_IPv6_headers);
            
            // add IPv6 fragmentation header
            click_ip6_fragment* ip6_frag_header = (click_ip6_fragment*) ((uint8_t*) ip6_packet + size_of_IPv6_headers);
            ip6_frag_header->ip6_frag_nxt = nxt;    // The Next Header value that identifies the first header of the Fragmentable Part of the original packet.
            if (i != (size_of_big_payload / size_of_data_part) + 1) {
    	        ip6_frag_header->ip6_frag_offset = ((((i-1) * (size_of_data_part/8)) << 3) & 0b1111111111111110);            
            } else {
                ip6_frag_header->ip6_frag_offset = ((((i-1) * (size_of_data_part/8)) << 3) | 0b0000000000000001);
            }
            
            // add data
            uint8_t* ip6_data = (uint8_t*) (ip6_frag_header + 1);
            memcpy(ip6_data, IPv6_payload + ((i-1) * size_of_data_part), size_of_data_part - sizeof(click_ip6_fragment)); // TODO only 24 bytes off at the moment
            output(0).push(packet);
        }
        click_chatter("done");
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Fragmenter)

#ifndef CLICK_MARKIP6HEADER_HH
#define CLICK_MARKIP6HEADER_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * MarkIP6Header([OFFSET,EXT_HDR_LNGTH])
 * =s ip6
 * Sets an IPv6 packet's network header and transport header pointer
 * =d
 * Sets the packet's network header pointer by assuming that the IPv6 header
 * starts at OFFSET bytes into the packet. Default OFFSET is 0.
 *
 * If IPv6 extension headers are used, give the total length (in bytes) of all
 * extension headers in this packet combined. This data is used to determine where the 
 * transport header starts. Default EXT_HDR_LNGTH is 0 which means it assumes that the transport
 * layer pointer comes right after the basic IPv6 header and no extension headers were
 * present.
 *
 * If extension headers are possible and the length of the extension headers is not known, 
 * please use MarkIP6Header2.
 * 
 * Does not check length fields for sanity or shorten packets to the IP length; use
 * CheckIPHeader or CheckIPHeader2 for that.
 *
 * =a CheckIP6Header, CheckIP6Header2, StripIP6Header */

class MarkIP6Header : public Element {

  int _offset;

 public:

  MarkIP6Header();
  ~MarkIP6Header();

  const char *class_name() const		{ return "MarkIP6Header"; }
  const char *port_count() const		{ return PORTS_1_1; }
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  Packet *simple_action(Packet *);
  
  private:
  
  bool list_contains_value(Vector<uint8_t> list, uint8_t nxt);

};

CLICK_ENDDECLS
#endif

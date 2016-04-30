#ifndef CLICK_MARKIPHEADER_HH
#define CLICK_MARKIPHEADER_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * MarkIPHeader([OFFSET])
 * =s ip
 * sets the packet's network header and transport header pointers
 * =d
 *
 * Sets the packet's network header pointer by assuming that the packet header
 * starts at OFFSET bytes into the packet. Default OFFSET is 0.
 *
 * Also at the same time sets the transport header pointer by looking to the 
 * ip Internet Header Length (IHL) field.
 *
 * Does not check length fields for sanity, shorten packets to the IP length,
 * or set the destination IP address annotation. Use CheckIPHeader or
 * CheckIPHeader2 for that.
 *
 * =a CheckIPHeader, CheckIPHeader2, StripIPHeader */

class MarkIPHeader : public Element {

  int _offset;

 public:

  MarkIPHeader() CLICK_COLD;
  ~MarkIPHeader() CLICK_COLD;

  const char *class_name() const		{ return "MarkIPHeader"; }
  const char *port_count() const		{ return PORTS_1_1; }
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  Packet *simple_action(Packet *);

};

CLICK_ENDDECLS
#endif

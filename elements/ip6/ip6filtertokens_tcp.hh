#ifndef IP6FILTER_TOKENS_TCP
#define IP6FILTER_TOKENS_TCP

#include "ip6filtertokens.hh"
#include "ip6filter_operator.hh"
#include <clicknet/tcp.h>

CLICK_DECLS

namespace ip6filtering {

enum TCPOptionName {
    SYN,
    FIN,
    ACK,
    RST,
    PSH,
    URG
};

/*
 * @brief A Token representing an TCP option name, a Primitive that does not hold an Opertator.
 * Whenever we see in our text something of the form "tcp opt" followed by a TCP option. The TCP Options are 'syn', 'fin', 'ack', 'rst', 'psh' and 'urg'.
 * Examples of TCPOptionNamePrimitiveTokens are "tcp opt fin" and "tcp opt ack".
 */
class TCPOptionNamePrimitiveToken : public PrimitiveToken {
public:
    TCPOptionNamePrimitiveToken(TCPOptionName tcp_option_name, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), tcp_option_name(tcp_option_name) { }
    virtual ~TCPOptionNamePrimitiveToken() {}
    
    virtual TCPOptionNamePrimitiveToken* clone_and_invert_not_keyword_seen() {
        if (this->is_preceded_by_not_keyword) {
            return new TCPOptionNamePrimitiveToken(this->tcp_option_name, false, this->an_operator); // not keyword seen is now inverted to false
        } else {
            return new TCPOptionNamePrimitiveToken(this->tcp_option_name, true, this->an_operator);  // not keyword seen is now inverted to true
        }
    }
    
    virtual bool check_whether_packet_matches(Packet *packet) {
        (void) packet;
//        click_tcp* tcp_header_of_this_packet = (click_tcp*) packet->tcp_header();    
    
        switch (tcp_option_name) {
            case SYN:
                return take_inverse_on_not(true); // normally we simply give back the answer of the equality but when the not
                                                                                                // keyword was seen we give back the inverse of this
            case FIN:
                return take_inverse_on_not(true);
            
            case ACK:
                return take_inverse_on_not(true);
                
            case RST:
                return take_inverse_on_not(true);
                
            case PSH:
                return take_inverse_on_not(true);
                
            default:   // It is an URG
                return take_inverse_on_not(true);
        }
    }
    
    virtual void print_name() {
        click_chatter("TCPOptionNamePrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an TCPOptionNamePrimitiveToken");
        PrimitiveToken::print();
    }
    
private:
    const TCPOptionName tcp_option_name;
};

class TCPReceiveWindowLengthPrimitiveToken : public PrimitiveToken {
public:
    TCPReceiveWindowLengthPrimitiveToken(uint16_t window_length, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), window_length(window_length) {}
    virtual ~TCPReceiveWindowLengthPrimitiveToken() { }
    
    virtual TCPReceiveWindowLengthPrimitiveToken* clone_and_invert_not_keyword_seen() {
        if (this->is_preceded_by_not_keyword) {
            return new TCPReceiveWindowLengthPrimitiveToken(this->window_length, false, this->an_operator); // not keyword seen is now inverted to false
        } else {
            return new TCPReceiveWindowLengthPrimitiveToken(this->window_length, true, this->an_operator);  // not keyword seen is now inverted to true
        }
    }

    virtual bool check_whether_packet_matches(Packet *packet) {
        click_tcp* tcp_header_of_this_packet = (click_tcp*) packet->tcp_header();
        
        switch (an_operator) {
            case EQUALITY:
                return take_inverse_on_not(tcp_header_of_this_packet->th_win == window_length); // normally we simply give back the answer of the equality but when the not
                                                                                                // keyword was seen we give back the inverse of this
            case INEQUALITY:
                return take_inverse_on_not(tcp_header_of_this_packet->th_win != window_length);
            
            case GREATER_THAN:
                return take_inverse_on_not(tcp_header_of_this_packet->th_win > window_length);
                
            case LESS_THAN:
                return take_inverse_on_not(tcp_header_of_this_packet->th_win < window_length);
                
            case GREATER_OR_EQUAL_THAN:
                return take_inverse_on_not(tcp_header_of_this_packet->th_win >= window_length);
                
            default:   // It is an LESS_OR_EQUAL_THAN
                return take_inverse_on_not(tcp_header_of_this_packet->th_win <= window_length);
        }
    }

    virtual void print_name() {
        click_chatter("TCPReceiveWindowLengthPrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an TCPReceiveWindowLengthPrimitiveToken");
        PrimitiveToken::print();
    }
    
private:
    uint16_t window_length;
};

};

CLICK_ENDDECLS

#endif /* IP6FILTER_TOKENS_TCP */

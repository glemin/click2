#ifndef IP6FILTER_TOKENS_IP
#define IP6FILTER_TOKENS_IP

#include "ip6filtertokens.hh"
#include "ip6filter_operator.hh"

CLICK_DECLS

namespace ip6filtering {
/*
 * @brief A Token representing an IPv4 Host Primitive, a special kind of Primitive
 * Whenever we see in our text something of the form "host" followed by an IPv4 address, such as "host 10.1.1.1" or 
 * "host 105.52.7.1" we replace it by a HostPrimitiveToken.
 */
class IPHostPrimitiveToken : public PrimitiveToken {
public:
    /*
     * @brief constructor, Token can only be created by giving an IPv4 address to create the Token with. in_addr contains an IPv4 address.
     * @param ip_address contains an IPv4 address.
     * @param is_preceded_by_not_keyword true when this token was preceded by a not keyword, false otherwise
     * @param an_operator contains an operator that could be found between the keyword and the data. If nothing was found between the keyword and the data this keyword must be given the value EQUALITY_OPERATOR.     
     */
    IPHostPrimitiveToken(in_addr ip_address, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator) {
        this->ip_address = ip_address;
    }
    virtual ~IPHostPrimitiveToken() {}
    /*
     * @brief Clones this IPHostPrimitiveToken but inverts the not keyword seen value.
     * If the "not keyword" was seen, the clone will indicate that the keyword was not seen. If the "not keyword" was not seen, the clone will indicate that the keyword was seen.
     * @return A clone of the node but with the not keyword seen value inverted.
     */
    virtual IPHostPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPHostPrimitiveToken(this->ip_address, !this->is_preceded_by_not_keyword, this->an_operator);
    }

    virtual void print_name() {
        click_chatter("IPHostPrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPHostPrimitiveToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        uint32_t* network_header_of_this_packet = (uint32_t*) packet->network_header();
        
        switch (an_operator)
        {
            case EQUALITY:
                // Either the source address of this packet is equal to the ip address given beforehand, or the destination address of the packet is equal to the ip address give beforehand
                // network_header_of_this_packet[3] contains the source address of this packet
                // network_header_of_this_packet[4] contains the destination address of this packet
                // ip_address.s_addr always contains the one address the user has already given beforehand
                if (!this->is_preceded_by_not_keyword) {        
                    return ((network_header_of_this_packet[3] == ip_address.s_addr) || (network_header_of_this_packet[4] == ip_address.s_addr));
                }
                return !((network_header_of_this_packet[3] == ip_address.s_addr) || (network_header_of_this_packet[4] == ip_address.s_addr));
            case INEQUALITY:
                 if (!this->is_preceded_by_not_keyword) {        
                    return ((network_header_of_this_packet[3] != ip_address.s_addr) || (network_header_of_this_packet[4] != ip_address.s_addr));
                }
                return !((network_header_of_this_packet[3] != ip_address.s_addr) || (network_header_of_this_packet[4] != ip_address.s_addr));               
            case GREATER_THAN:
                if (!this->is_preceded_by_not_keyword) {        
                    return ((network_header_of_this_packet[3] > ip_address.s_addr) || (network_header_of_this_packet[4] > ip_address.s_addr));
                }
                return !((network_header_of_this_packet[3] > ip_address.s_addr) || (network_header_of_this_packet[4] > ip_address.s_addr));
            case GREATER_OR_EQUAL_THAN:
                if (!this->is_preceded_by_not_keyword) {        
                    return ((network_header_of_this_packet[3] >= ip_address.s_addr) || (network_header_of_this_packet[4] >= ip_address.s_addr));
                }
                return !((network_header_of_this_packet[3] >= ip_address.s_addr) || (network_header_of_this_packet[4] >= ip_address.s_addr));                
            case LESS_THAN:
                if (!this->is_preceded_by_not_keyword) {
                    return ((network_header_of_this_packet[3] < ip_address.s_addr) || (network_header_of_this_packet[4] < ip_address.s_addr));
                }
                return !((network_header_of_this_packet[3] < ip_address.s_addr) || (network_header_of_this_packet[4] < ip_address.s_addr));                
            default:    // It is LESS_OR_EQUAL_THAN
                 if (!this->is_preceded_by_not_keyword) {
                    return ((network_header_of_this_packet[3] <= ip_address.s_addr) || (network_header_of_this_packet[4] <= ip_address.s_addr));
                }
                return !((network_header_of_this_packet[3] <= ip_address.s_addr) || (network_header_of_this_packet[4] <= ip_address.s_addr));
        }
    }
private:
    in_addr ip_address;
};

/*
 * @brief A token representing an IPv4 Src Host Primitive, a special kind of Primitive
 * Whenever we see in our text something of the form "src host" followed by an IPv4 address, such as "src host 10.1.2.3" or
 * "src host 105.20.33.7" we replace it by a SrcHostPrimitiveToken
 */ 
class IPSrcHostPrimitiveToken: public PrimitiveToken {
public:
    /*
     * @brief constructor, Token can only be created by giving an IPv4 address to create the Token with. in_addr contains an IPv4 address.
     * @param ip_address contains an IPv4 address.
     * @param is_preceded_by_not_keyword true when this token was preceded by a not keyword, false otherwise
     * @param an_operator contains an operator that could be found between the keyword and the data. If nothing was found between the keyword and the data this keyword must be given the value EQUALITY_OPERATOR.
     */
    IPSrcHostPrimitiveToken(in_addr ip_address, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator) {
        this->ip_address = ip_address;
    }
    virtual ~IPSrcHostPrimitiveToken() {}
    /*
     * @brief Clones this IPSrcHostPrimitiveToken but inverts the not keyword seen value.
     * If the "not keyword" was seen, the clone will indicate that the keyword was not seen. If the "not keyword" was not seen, the clone will indicate that the keyword was seen.
     * @return A clone of the node but with the not keyword seen value inverted.
     */
    virtual IPSrcHostPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPSrcHostPrimitiveToken(this->ip_address, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    
    virtual void print_name() {
        click_chatter("IPSrcHostPrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPSrcHostPrimitiveToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        uint32_t* network_header_of_this_packet = (uint32_t*) packet->network_header();
        
        switch (an_operator)
        {
            case EQUALITY:
                // The source address of this packet must be equal to the ip address given beforehand
                // network_header_of_this_packet[3] contains the source address of this packet
                // ip_address.s_addr contains the one address the user has already given beforehand        
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[3] == ip_address.s_addr);
                }
                return !(network_header_of_this_packet[3] == ip_address.s_addr);
            case INEQUALITY:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[3] != ip_address.s_addr);
                }
                return !(network_header_of_this_packet[3] != ip_address.s_addr);                
            case GREATER_THAN:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[3] > ip_address.s_addr);
                }
                return !(network_header_of_this_packet[3] > ip_address.s_addr);
            case GREATER_OR_EQUAL_THAN:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[3] >= ip_address.s_addr);
                }
                return !(network_header_of_this_packet[3] >= ip_address.s_addr);
            case LESS_THAN:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[3] < ip_address.s_addr);
                }
                return !(network_header_of_this_packet[3] < ip_address.s_addr);
            default:   // It is LESS_OR_EQUAL_THAN
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[3] <= ip_address.s_addr);
                }
                return !(network_header_of_this_packet[3] <= ip_address.s_addr);
        }
    }
private:
    in_addr ip_address;
};

/*
 * @brief A token representing an IPv4 Dst Host Primitive, a special kind of Primitive
 * Whenever we see in our text something of the form "dst host" followed by an IPv4 address, such as "dst host 12.11.2.7" or
 * "dst host 109.3.74.5" we replace it by a DstHostPrimitiveToken
 */ 
class IPDstHostPrimitiveToken : public PrimitiveToken {
public:
    /*
     * @brief constructor, Token can only be created by giving an IPv4 address to create the Token with. in_addr contains an IPv4 address.
     * @param ip_address contains an IPv4 address.
     * @param is_preceded_by_not_keyword true when this token was preceded by a not keyword, false otherwise
     * @param an_operator contains an operator that could be found between the keyword and the data. If nothing was found between the keyword and the data this keyword must be given the value EQUALITY_OPERATOR.
     */
    IPDstHostPrimitiveToken(in_addr ip_address, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator) {
        this->ip_address = ip_address;
    }
    virtual ~IPDstHostPrimitiveToken() {}
     /*
     * @brief Clones this IPDstHostPrimitiveToken but inverts the not keyword seen value.
     * If the "not keyword" was seen, the clone will indicate that the keyword was not seen. If the "not keyword" was not seen, the clone will indicate that the keyword was seen.
     * @return A clone of the node but with the not keyword seen value inverted.
     */
    virtual IPDstHostPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPDstHostPrimitiveToken(this->ip_address, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    virtual void print_name() {
        click_chatter("IPDstHostPrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPDstHostPrimitiveToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        uint32_t* network_header_of_this_packet = (uint32_t*) packet->network_header();
        
        switch (an_operator)
        {
            case EQUALITY:
                // The destination address of this packet must be equal to the ip address given beforehand
                // network_header_of_this_packet[4] contains the destination address of this packet
                // ip_address.s_addr contains the one address the user has already given beforehand
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[4] == ip_address.s_addr);
                } else {
                    return !(network_header_of_this_packet[4] == ip_address.s_addr);
                }
            case INEQUALITY:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[4] == ip_address.s_addr);
                } else {
                    return !(network_header_of_this_packet[4] == ip_address.s_addr);
                }                
            case GREATER_THAN:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[4] > ip_address.s_addr);
                }
                return !(network_header_of_this_packet[4] > ip_address.s_addr);
            case GREATER_OR_EQUAL_THAN:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[4] >= ip_address.s_addr);
                }
                return !(network_header_of_this_packet[4] >= ip_address.s_addr);
            case LESS_THAN:
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[4] < ip_address.s_addr);
                }
                return !(network_header_of_this_packet[4] < ip_address.s_addr);
            default:   // It is LESS_OR_EQUAL_THAN
                if (!this->is_preceded_by_not_keyword) {
                    return (network_header_of_this_packet[4] <= ip_address.s_addr);
                }
                return !(network_header_of_this_packet[4] <= ip_address.s_addr);
        }
    }
private:
    in_addr ip_address;
};

class IPVersionPrimitiveToken : public PrimitiveToken {
public:
    IPVersionPrimitiveToken(uint8_t version, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), version(version) { }
    virtual ~IPVersionPrimitiveToken() { }
    virtual IPVersionPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPVersionPrimitiveToken(this->version, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    
    virtual void print_name() {
        click_chatter("IPVersionToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPVersionToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        switch (an_operator)
        {
        case EQUALITY:
            return take_inverse_on_not(network_header_of_this_packet->ip_v == version);
        case INEQUALITY:
            return take_inverse_on_not(network_header_of_this_packet->ip_v != version);
        case GREATER_THAN:
            return take_inverse_on_not(network_header_of_this_packet->ip_v > version);
        case LESS_THAN:
            return take_inverse_on_not(network_header_of_this_packet->ip_v < version);
        case GREATER_OR_EQUAL_THAN:
            return take_inverse_on_not(network_header_of_this_packet->ip_v >= version);
        default:    // LESS_OR_EQUAL_THAN
            return take_inverse_on_not(network_header_of_this_packet->ip_v <= version);
        }
    }       
private:
    uint8_t version;
};

class IPHeaderLengthPrimitiveToken : public PrimitiveToken {
public:
    IPHeaderLengthPrimitiveToken(uint8_t header_length, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), header_length(header_length) { }
    virtual ~IPHeaderLengthPrimitiveToken() { }
    virtual IPHeaderLengthPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPHeaderLengthPrimitiveToken(this->header_length, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    
    virtual void print_name() {
        click_chatter("IPHeaderLengthToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPHeaderLengthToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        switch (an_operator)
        {
        case EQUALITY:
            return take_inverse_on_not(network_header_of_this_packet->ip_hl == header_length);
        case INEQUALITY:
            return take_inverse_on_not(network_header_of_this_packet->ip_hl != header_length);
        case GREATER_THAN:
            return take_inverse_on_not(network_header_of_this_packet->ip_hl > header_length);
        case LESS_THAN:
            return take_inverse_on_not(network_header_of_this_packet->ip_hl < header_length);
        case GREATER_OR_EQUAL_THAN:
            return take_inverse_on_not(network_header_of_this_packet->ip_hl >= header_length);
        default:    // LESS_OR_EQUAL_THAN
            return take_inverse_on_not(network_header_of_this_packet->ip_hl <= header_length);
        }
    }    
private:
    uint8_t header_length;
};

class IPIDPrimitiveToken : public PrimitiveToken {
public:
    IPIDPrimitiveToken(uint16_t identification, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), identification(identification) { }
    virtual ~IPIDPrimitiveToken() { }
    virtual IPIDPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPIDPrimitiveToken(this->identification, !this->is_preceded_by_not_keyword, this->an_operator);
    }    
    
    virtual void print_name() {
        click_chatter("IPIDToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPIDToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        switch (an_operator)
        {
        case EQUALITY:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_id) == identification);
        case INEQUALITY:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_id) != identification);
        case GREATER_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_id) > identification);
        case LESS_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_id) < identification);
        case GREATER_OR_EQUAL_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_id) >= identification);
        default:    // LESS_OR_EQUAL_THAN
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_id) <= identification);
        }
    }
private:
    uint16_t identification;
};

class IPTOSPrimitiveToken : public PrimitiveToken {
public:
    IPTOSPrimitiveToken(uint8_t tos, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), tos(tos) { }
    virtual ~IPTOSPrimitiveToken() { }
    virtual IPTOSPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPTOSPrimitiveToken(this->tos, !this->is_preceded_by_not_keyword, this->an_operator);
    }        
    
    virtual void print_name() {
        click_chatter("IPTOSToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPTOSToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        switch (an_operator)
        {
        case EQUALITY:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos) == tos);
        case INEQUALITY:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos) != tos);
        case GREATER_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos) > tos);
        case LESS_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos) < tos);
        case GREATER_OR_EQUAL_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos) >= tos);
        default:    // LESS_OR_EQUAL_THAN
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos) <= tos);
        }
    }                
private:
    uint8_t tos;
};

class IPDSCPPrimitiveToken : public PrimitiveToken {
public:
    IPDSCPPrimitiveToken(uint8_t dscp, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), dscp(dscp) { }
    virtual ~IPDSCPPrimitiveToken() { }
    virtual IPDSCPPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPDSCPPrimitiveToken(this->dscp, !this->is_preceded_by_not_keyword, this->an_operator);
    }           
    
    virtual void print_name() {
        click_chatter("IPDSCPToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPDSCPToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        switch (an_operator)
        {
        case EQUALITY:
            return take_inverse_on_not((htons(network_header_of_this_packet->ip_tos & 0b11111100) >> 2) == dscp);
        case INEQUALITY:
            return take_inverse_on_not((htons(network_header_of_this_packet->ip_tos & 0b11111100) >> 2) != dscp);
        case GREATER_THAN:
            return take_inverse_on_not((htons(network_header_of_this_packet->ip_tos & 0b11111100) >> 2) > dscp);
        case LESS_THAN:
            return take_inverse_on_not((htons(network_header_of_this_packet->ip_tos & 0b11111100) >> 2) < dscp);
        case GREATER_OR_EQUAL_THAN:
            return take_inverse_on_not((htons(network_header_of_this_packet->ip_tos & 0b11111100) >> 2) >= dscp);
        default:    // LESS_OR_EQUAL_THAN
            return take_inverse_on_not((htons(network_header_of_this_packet->ip_tos & 0b11111100) >> 2) <= dscp);
        }      
    }        
private:
    uint8_t dscp;
};

class IPECNPrimitiveToken : public PrimitiveToken {
public:
    IPECNPrimitiveToken(uint8_t ecn, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), ecn(ecn) { }
    virtual ~IPECNPrimitiveToken() { }
    virtual IPECNPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPECNPrimitiveToken(this->ecn, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    
    virtual void print_name() {
        click_chatter("IPECNToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPECNToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        switch (an_operator)
        {
        case EQUALITY:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos & 0b00000011) == ecn);
        case INEQUALITY:
             return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos & 0b00000011) != ecn);       
        case GREATER_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos & 0b00000011) > ecn);        
        case LESS_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos & 0b00000011) < ecn);        
        case GREATER_OR_EQUAL_THAN:
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos & 0b00000011) >= ecn);        
        default:    // LESS_OR_EQUAL_THAN
            return take_inverse_on_not(htons(network_header_of_this_packet->ip_tos & 0b00000011) <= ecn);            
        }
    }       
private:
    uint8_t ecn;
};

class IPCEPrimitiveToken : public PrimitiveToken {
public:
    IPCEPrimitiveToken(bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator) { }
    virtual ~IPCEPrimitiveToken() { }
    virtual IPCEPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPCEPrimitiveToken(!this->is_preceded_by_not_keyword, this->an_operator);
    }
    
    virtual void print_name() {
        click_chatter("IPCEToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPCEToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        return take_inverse_on_not((network_header_of_this_packet->ip_tos & 0b00000011) == 0b00000011);
    }
};

class IPTTLPrimitiveToken : public PrimitiveToken {
public:
    IPTTLPrimitiveToken(uint8_t ttl, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), ttl(ttl) { }
    virtual ~IPTTLPrimitiveToken() { }
    virtual IPTTLPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPTTLPrimitiveToken(ttl, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    
    virtual void print_name() {
        click_chatter("IPTTLToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPTTLToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        return take_inverse_on_not(network_header_of_this_packet->ip_ttl == ttl);
    }
private:
    uint8_t ttl;    // time to live
};

class IPFragPrimitiveToken : public PrimitiveToken {
public:
    IPFragPrimitiveToken(bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator) { }
    virtual ~IPFragPrimitiveToken() { }
    virtual IPFragPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPFragPrimitiveToken(!this->is_preceded_by_not_keyword, this->an_operator);
    }
    
    virtual void print_name() {
        click_chatter("IPFragToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPFragToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        (void) packet;
        return true;
    }    
};

class IPUnfragPrimitiveToken : public PrimitiveToken {
public:
    IPUnfragPrimitiveToken(bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator) { }
    virtual ~IPUnfragPrimitiveToken() { }
    virtual IPUnfragPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPUnfragPrimitiveToken(!this->is_preceded_by_not_keyword, this->an_operator);
    }
        
    virtual void print_name() {
        click_chatter("IPUnfragToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPUnfragToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        (void) packet;
        return true;
    }    
};

/*
 * @brief A Token representing an IPv4 Net Primitive, a special kind of Primitive
 * This token is used to check whether the packet source or destination address belongs to a certain IPv4 network
 * Whenever we see in our text something of the form "net" followed by an IPv4 address, such as "net 10.1.0.0/24", or 
 * "net mask 105.52.7.1" we replace it by a IPNetPrimitiveToken.
 */
class IPNetPrimitiveToken : public PrimitiveToken {
public:
    IPNetPrimitiveToken(IPAddress address, IPAddress mask, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), address(address), mask(mask) { }
    virtual ~IPNetPrimitiveToken() { }
    virtual IPNetPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPNetPrimitiveToken(address, mask, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    virtual void print_name() {
        click_chatter("IPNetPrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPNetPrimitiveToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        return take_inverse_on_not((network_header_of_this_packet->ip_src & mask) == (address & mask) || (network_header_of_this_packet->ip_dst & mask) == (address & mask));
    }
private:
    IPAddress address;
    IPAddress mask;
};

/*
 * @brief A Token representing an IPv4 Src Net Primitive, a special kind of Primitive
 * This token is used to check whether the packet source address belongs to a certain IPv4 network
 * Whenever we see in our text something of the form "src net" followed by an IPv4 address, such as "src net 12.5.0.0/24", or 
 * "src net 12.5.0.0 mask 255.255.255.0" we replace it by a IPSrcNetPrimitiveToken.
 */
class IPSrcNetPrimitiveToken : public PrimitiveToken {
public:
    IPSrcNetPrimitiveToken(IPAddress address, IPAddress mask, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), address(address), mask(mask) { }
    virtual ~IPSrcNetPrimitiveToken() { }
    virtual IPSrcNetPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPSrcNetPrimitiveToken(address, mask, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    
        virtual void print_name() {
        click_chatter("IPSrcNetPrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPSrcNetPrimitiveToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        return take_inverse_on_not((network_header_of_this_packet->ip_src & mask) == (address & mask));
    }
private:
    IPAddress address;
    IPAddress mask;
};

/*
 * @brief A Token representing an IPv4 Dst Net Primitive, a special kind of Primitive
 * This token is used to check whether the packet destination address belongs to a certain IPv4 network
 * Whenever we see in our text something of the form "dst net" followed by an IPv4 address, such as "dst net 12.5.0.0/24", or 
 * "dst net 12.5.0.0 mask 255.255.255.0" we replace it by a IPDstNetPrimitiveToken.
 */
class IPDstNetPrimitiveToken : public PrimitiveToken {
public:
    IPDstNetPrimitiveToken(IPAddress address, IPAddress mask, bool is_preceded_by_not_keyword, Operator an_operator) : PrimitiveToken(is_preceded_by_not_keyword, an_operator), address(address), mask(mask) { }
    virtual ~IPDstNetPrimitiveToken() { }
    virtual IPDstNetPrimitiveToken* clone_and_invert_not_keyword_seen() {
        return new IPDstNetPrimitiveToken(address, mask, !this->is_preceded_by_not_keyword, this->an_operator);
    }
    virtual void print_name() {
        click_chatter("IPDstNetPrimitiveToken");
    }
    virtual void print() {
        click_chatter("We encountered an IPDstNetPrimitiveToken");
        PrimitiveToken::print();
    }
    virtual bool check_whether_packet_matches(Packet *packet) {
        click_ip *network_header_of_this_packet = (click_ip*) packet->network_header();
        return take_inverse_on_not((network_header_of_this_packet->ip_dst & mask) == (address & mask));
    }
private:
    IPAddress address;
    IPAddress mask;
};

};

CLICK_ENDDECLS

#endif /* IP6FILTER_TOKENS_IP */

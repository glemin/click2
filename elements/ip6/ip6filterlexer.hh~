#ifndef CLICK_IP6FILTER_LEXER_HH
#define CLICK_IP6FILTER_LEXER_HH

#include <click/config.h>
#include <click/vector.hh>
#include <click/string.hh>
#include <click/error.hh>
#include "ip6filtertokens.hh"
#include "ip6filtertokens_ip.hh"
#include "ip6filtertokens_ip6.hh"
#include "ip6filtertokens_icmp.hh"
#include "ip6filtertokens_tcp.hh"
#include "ip6filtertokens_tcp_udp.hh"
#include "ip6filterfactories.hh"
CLICK_DECLS

namespace ip6filtering {
/* for documentation see ip6filterlexer.cc */
int skip_blanks(String to_be_lexed_string, int i);

/* for documentation see ip6filterlexer.cc */
int read_word(String to_be_lexed_string, int i, String& read_word);

/* for documentation see ip6filterlexer.cc, note: this function throws an exception */
void skip_blanks_and_read_word(String to_be_lexed_string, int& i, String& read_word, const String error);

/* for documentation see ip6filterlexer.cc */
int is_word_an_operator(String word, Operator& an_operator);

/*
 * @brief This class represents a Lexer that is used to lex a to be lexed string and split it up into a list of tokens tokens.
 * This specific Lexer is the Lexer associated with the IPFilter class.
 * For more information on how the tokens might look like, go the the lex function Vector<String> lex().
 */
class Lexer {
public:
    Lexer(String to_be_lexed_string);
    ~Lexer();
    int lex(Vector<Token*>& tokens, ErrorHandler *errh);
private:
    String to_be_lexed_string;
};

};

CLICK_ENDDECLS
#endif /* CLICK_IP6FILTER_LEXER_HH */

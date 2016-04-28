#ifndef CLICK_IP6FILTER_PARSE_STACK_HH
#define CLICK_IP6FILTER_PARSE_STACK_HH
#include <click/config.h>
#include <click/vector.hh>
#include <click/error.hh>
#include "ip6filtertokens.hh"
CLICK_DECLS

namespace ip6filtering {
    /* for documentation see ip6filterparsestack.cc */
    int create_negated_node(ASTNode *original_node, ASTNode &negated_node);

    class ParseStack {
    public:
        int push_on_stack_and_possibly_evaluate(Token *token, ErrorHandler *errh);
        int get_AST(AST &ast, ErrorHandler *errh);
    private:
        int evaluate_end_of_line_version(ErrorHandler *errh);
        int evaluate_parenthesis_version(ErrorHandler *errh);
        int evaluate_common_part(int first_token_location, int last_token_location, bool is_called_by_parenthesis_version, ErrorHandler *errh);
        AST ast;
        Vector<Token*> stack;   // a vector simulating a stack
    };
};

CLICK_ENDDECLS
#endif /* CLICK_IP6FILTER_PARSE_STACK_HH */

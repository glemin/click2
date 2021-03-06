/*
 * ip6filter.{cc,hh} -- IP-packet filter with tcpdumplike syntax
 * Glenn Minne
 *
 * Copyright (c) 2000-2007 Mazu Networks, Inc.
 * Copyright (c) 2010 Meraki, Inc.
 * Copyright (c) 2004-2011 Regents of the University of California
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
#include "ip6filter.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/args.hh>
#include "ip6filterlexer.hh"
#include "ip6filterparser.hh"

CLICK_DECLS

IP6Filter::IP6Filter() {}

IP6Filter::~IP6Filter() {}

//
// CONFIGURATION
//

int
IP6Filter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    ErrorHandler *errh2 = ErrorHandler::default_handler();

    // Make an Abstract Syntax Tree for each output
    for (int i = 0; i < conf.size(); i++) {
        click_chatter("i = %i", i);
        ip6filtering::Lexer lexer(conf[i]);  // or host fe80:0000:0000:0000:0202:b3ff:fe1e:8329
        Vector<ip6filtering::Token*> tokens;
        int success = lexer.lex(tokens, errh2);
        if (success >= 0) {
            click_chatter("De tokens die in de lijst zaten zijn: ");
            for (int i = 0; i < tokens.size(); i++) {
                tokens[i]->print_name();
            }
            click_chatter("we hebben success gelijk aan %i , na de lexer", success);
            ip6filtering::Parser parser(tokens);
            ip6filtering::AST ast; // an abstract syntax tree
            success = parser.parse(ast, errh2);
            
            click_chatter("we hebben success gelijk aan %i , na de parser", success);
            if (success >= 0) {
                click_chatter("we gaan printen");
                ast.print();
                click_chatter("we hebben geprint");
                ast_list.push_back(ast);    // add this AST to the list of ASTs
            }
        }
        click_chatter("we zijn aan het einde van de configuration function gekomen");
    }
    return 0;
}

//
// RUNNING
//

void
IP6Filter::push(int, Packet *p)
{
    click_chatter("push packet");
    for (int i = 0; i < ast_list.size(); i++) {     // for each AST (abstract syntax tree) of the abstract syntax list do
        const bool matches = ast_list[i].check_whether_packet_matches(p);
        if (matches) {
            click_chatter("it matches"); 
        } else {
            click_chatter("it doesn't match");
        }
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(Classification)
EXPORT_ELEMENT(IP6Filter)

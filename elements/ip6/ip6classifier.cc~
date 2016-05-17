/*
 * ip6classifier.{cc,hh} -- IPv6-packet filter with tcpdumplike syntax
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
#include "ip6classifier.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/args.hh>
#include "ip6classifier_lexer.hh"
#include "ip6classifier_parser.hh"
#include <fstream>

CLICK_DECLS

IP6Classifier::IP6Classifier() {}

IP6Classifier::~IP6Classifier() {}

//
// CONFIGURATION
// In short: a) Take each pattern an divide it up into tokens
//           b) Pass the tokens to a Parser
//           c) The parser returns an Abstract Syntax Tree for each pattern
//           d) Use this Abstract Syntax Tree to match against packets in the push method
//

int
IP6Classifier::configure(Vector<String> &conf, ErrorHandler *errh)
{
    ErrorHandler *errh2 = ErrorHandler::default_handler();

    // Make an Abstract Syntax Tree for each output
    for (int i = 0; i < conf.size(); i++) {
        ip6classification::Lexer lexer(conf[i]);
        Vector<ip6classification::Token*> tokens;
        int success = lexer.lex(tokens, errh2);
        if (success >= 0) {
// USE BELOW FOR DEBUGGING TOKENS
//            click_chatter("The tokens in the list are: ");
//            for (int i = 0; i < tokens.size(); i++) {
//                tokens[i]->print_name();
//            }
            ip6classification::Parser parser(tokens);
            ip6classification::AST ast; // an abstract syntax tree
            success = parser.parse(ast, errh2);
            
            if (success >= 0) {
// USE BELOW FOR DEBUGGING ALREADY COMBINED TOKENS
//                ast.print();
                ast_list.push_back(ast);    // add this AST to the list of ASTs
            }
        }
    }
    return 0;
}

//
// RUNNING
// Here we do what was above described in d).
//

void
IP6Classifier::push(int, Packet *p)
{
//    click_chatter("_number_of_test_packets_sent = %i", _number_of_test_packets_sent);
    // start test
	if (_number_of_test_packets_sent < _number_of_test_packets_to_be_sent) {
        // add a timestamp to the timestamp vector
        _time_stamp_vector.push_back(Timestamp::now());
    }

    // start of original code
    for (int i = 0; i < ast_list.size(); i++) {     // for each AST (abstract syntax tree) of the abstract syntax list do
        const bool matches = ast_list[i].check_whether_packet_matches(p);
        if (matches) {
            output(i).push(p);
            
            // performance part inbetween
            if (_number_of_test_packets_sent < _number_of_test_packets_to_be_sent) {
                // add a timestamp to the timestamp vector
                _time_stamp_vector2.push_back(Timestamp::now());
	            _number_of_test_packets_sent++;
            } else if (_number_of_test_packets_sent == _number_of_test_packets_to_be_sent) {
                click_chatter("write into example 2");
                _number_of_test_packets_sent++;
                
                // write the data to a file
                std::ofstream myfile;
                myfile.open("example2.txt");
                for (int i = 0; i < _time_stamp_vector.size(); i++) {
                    myfile << _time_stamp_vector2[i].nsecval() - _time_stamp_vector[i].nsecval() << "\n";
                }
                myfile.close();
                
                // display average
                int64_t average = 0;
                for (int i = 0; i < _number_of_test_packets_to_be_sent; i++) {
                    average += ((_time_stamp_vector2[i].nsecval() - _time_stamp_vector[i].nsecval()));
                }
                average = average / (int64_t) _number_of_test_packets_to_be_sent;
                click_chatter("the average = %i ", average);
                std::ofstream myfile2;
                myfile2.open("average.txt");
                myfile2 << average << " ";
                myfile2.close();
                
                // close program
                exit(0);
            } else {
                // Do nothing
                // The performance test has been completed
                // The following packets coming in will be sent without keeping track of timestamps
            }                
            // end of the performance part inbetween
            return;
        }
    }
    // end of original code
    
    // end test
	if (_number_of_test_packets_sent < _number_of_test_packets_to_be_sent) {
        // add a timestamp to the timestamp vector
        _time_stamp_vector2.push_back(Timestamp::now());
	    _number_of_test_packets_sent++;
    } else if (_number_of_test_packets_sent == _number_of_test_packets_to_be_sent) {
        click_chatter("write into example 2");
        _number_of_test_packets_sent++;
        
        // write the data to a file
        std::ofstream myfile;
        myfile.open("example2.txt");
        for (int i = 0; i < _time_stamp_vector.size(); i++) {
            myfile << _time_stamp_vector2[i].nsecval() - _time_stamp_vector[i].nsecval() << "\n";
        }
        myfile.close();
        
        // display average
        int64_t average = 0;
        for (int i = 0; i < _number_of_test_packets_to_be_sent; i++) {
            average += ((_time_stamp_vector2[i].nsecval() - _time_stamp_vector[i].nsecval()));
        }
        average = average / (int64_t) _number_of_test_packets_to_be_sent;
        click_chatter("the average = %i ", average);
        std::ofstream myfile2;
        myfile2.open("average.txt");
        myfile2 << average << " ";
        myfile2.close();
        
        // close program
        exit(0);
    } else {
        // Do nothing
        // The performance test has been completed
        // The following packets coming in will be sent without keeping track of timestamps
    }    
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Classifier)

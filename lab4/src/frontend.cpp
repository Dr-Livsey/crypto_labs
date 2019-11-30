#include "algo.h"
#include "file.h"
#include "text.h"
#include "subst.h"
#include "fdict.h"
#include "frontend.h"
#include "nlohmann/json.hpp"

#include <string>
#include <iostream>
#include <regex>

using     json   = nlohmann::json;
namespace parser = frontend::parser;

int
frontend::run( void )
{
    while ( true )
    {
        std::cout << "\n> ";

        std::string cmd_line;
        std::getline(std::cin, cmd_line);

        if (cmd_line == "quit") return EXIT_SUCCESS;

        try
        {
            parser::value_map cmd_map = parser::parse(cmd_line, parser::ptype::interactive);

            if ( cmd_map.at("method") == "help" ){
                help();
            } 
            else {
                execute_command(cmd_map);
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << std::endl << "(Exception)\n" << e.what() << '\n';
        }
    }

    return EXIT_SUCCESS;
}

int
frontend::run(int argc, char *argv[])
{
    std::string cmd_line;

    for ( int i = 1; i < argc; i++ ) cmd_line += std::string(argv[i]) + " ";

    if (cmd_line.empty())
        return frontend::run();
    else
    {
        try
        {
            return execute_command(parser::parse(cmd_line, parser::ptype::forward));
        }
        catch(const std::exception& e)
        {
            std::cerr << "(Exception): " << e.what() << '\n';
        }
    }

    return EXIT_FAILURE;
}

int
frontend::execute_command( const parser::value_map &val_map)
{
    // Set general parameters
    std::string  method = val_map.at("method");
    
    if (method == "encrypt" || method == "decrypt")
    {
        // Read input text
        crypto::file  input_file(val_map.at("file"));
        crypto::text  input_text(input_file);

        //Set key
        crypto::file key_file(val_map.at("key file"));
        sp_cypher::key key = key_file;

        // Set S-substitution
        sp_cypher::subst S("src/sub.json");

        // Set counter
        crypto::file init_vector_file("src/IV.txt");
        sp_cypher::counter cnt(init_vector_file);

        crypto::text output;
        
        if ( method == "encrypt" )
            output = sp_cypher::encrypt::algo(key, input_text, S, cnt);
        else
            output = sp_cypher::decrypt::algo(key, input_text, S, cnt);

        // Putting the result into output file
        crypto::file output_file(val_map.at("dest"), std::ios::out | std::ios::binary);
        output_file << output;

        std::cout << "Output was putted in \"" << val_map.at("dest") << "\"" << std::endl;
    }
    else if ( method == "alph" )
    {
        // Read input text
        crypto::file  input_file(val_map.at("file"));
        crypto::text  input_text(input_file);

        crypto::fdict freqs(input_text);

        crypto::file output_file(val_map.at("dest (*.json)"), std::ios::out | std::ios::binary);
        output_file << freqs;

        std::cout << "Frequencies was putted in \"" << val_map.at("dest (*.json)") << "\"" << std::endl;
    }
    else if ( method == "find" )
    {
        /*
         * Open S-subst and dest file
         */
        sp_cypher::subst s_sub = val_map.at("sub");
        crypto::file dest_file(val_map.at("dest"), std::ios::app | std::ios::binary);

        if (val_map.at("what") == "weak-keys")
        {
            sp_cypher::find_weak_keys(s_sub, dest_file);
        }
        else if (val_map.at("what") == "error_prop")
        {
            sp_cypher::error_prop(s_sub, dest_file);
        }
        else {
            std::cout << "Unknown method. Available: [weak-keys], [error_prop]" << std::endl;
        }
    }

    return EXIT_SUCCESS;
}

parser::tokens
parser::split( const std::string &str, const std::string &delimiters )
{
    tokens retval;

    std::regex  pattern_str("[" + delimiters + "]+");

    using token_iterator = std::regex_token_iterator<std::string::const_iterator>;

    std::copy( token_iterator(str.cbegin(), str.cend(), pattern_str, -1),
               token_iterator(),
               std::back_inserter(retval));

    return retval;
}

parser::value_map
parser::parse( const std::string &raw_line, parser::ptype t )
{
    // Split line into tokens
    tokens toks = split(raw_line);

    // Loading parse tree
    crypto::file parse_tree_file("src/parse_tree.json");

    json parse_tree;
    parse_tree_file >> parse_tree;
    parse_tree = parse_tree.at(toks.front());

    // Reading values
    value_map retmap;
    retmap["method"] = toks.front();

    if ( retmap["method"] == "help" ){
        return retmap;
    }
    
    for ( auto json_it = parse_tree.cbegin(); json_it != parse_tree.cend(); json_it++ )
    {
        token value;

        if ( t == parser::ptype::interactive )
        {
            std::cout << "\t" << *json_it << "\n";
            std::cout << "\t" << "# ";
            std::getline(std::cin, value);
            std::cout << "\n";
        }
        else if ( t == parser::ptype::forward )
        {
            std::size_t tok_idx = std::stoul(json_it.key(), nullptr);
            value = toks.at(tok_idx);

            std::cout << *json_it << " : " << value << std::endl;
        }

        retmap[*json_it] = value;
    }

    std::cout << std::endl;
    return retmap;
}

void
frontend::help()
{
    std::cout << "\tencrypt - Encrypt file with SP algorithm + whitening" << std::endl;
    std::cout << "\tdecrypt - Decrypt file with SP algorithm + whitening" << std::endl;
    std::cout << std::endl;
}
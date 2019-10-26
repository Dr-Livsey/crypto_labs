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
        return execute_command(parser::parse(cmd_line, parser::ptype::forward));
    }

    return EXIT_FAILURE;
}

int
frontend::execute_command( const parser::value_map &val_map)
{
    // Set general parameters
    crypto::file input_file(val_map.at("file"));
    std::string  method = val_map.at("method");
    
    // Read input text
    crypto::text  input_text(input_file);

    if (method == "encrypt" || method == "decrypt")
    {
        //Set key
        sp_cypher::key key = val_map.at("key");

        // Set S-substitution
        sp_cypher::subst S("src/sub.json");

        if (key.none()){
            throw std::runtime_error("Key is empty!");
        }

        crypto::text output;
        
        if ( method == "encrypt" )
            output = sp_cypher::encrypt(key, input_text, S);
        else
            output = sp_cypher::decrypt(key, input_text, S);

        // Putting the result into output file
        crypto::file output_file(val_map.at("dest"), std::ios::out | std::ios::binary);
        output_file << output;

        std::cout << "Output was putted in \"" << val_map.at("dest") << "\"" << std::endl;
    }
    else if ( method == "alph" )
    {
        crypto::fdict freqs(input_text);

        crypto::file output_file(val_map.at("dest (*.json)"), std::ios::out | std::ios::binary);
        output_file << freqs;

        std::cout << "Frequencies was putted in \"" << val_map.at("dest (*.json)") << "\"" << std::endl;
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
#include "file.h"
#include "algo.h"
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

        try
        {
            parser::value_map cmd_map = parser::parse(cmd_line);

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
frontend::execute_command( const parser::value_map &val_map)
{
    // Set general parameters
    crypto::file input_file(val_map.at("file"));
    std::string  method = val_map.at("method");
    
    // Read input text
    crypto::text  input_text(input_file);

    if (method == "encrypt")
    {
        std::string algo = val_map.at("algo");

        // Set alphabet
        crypto::alph alph = crypto::fdict::get_freq(input_text).keys();

        //Set key
        crypto::key key;
        if ( val_map.at("key") == "" )
        {
            // If Vigenere use predefined key use predefined key (21, 3, 7, 11, 23)
            if ( std::regex_match(algo, std::regex("vig.*")) )
            {
                std::cout << "Using predefined key:\n";          
                if ( alph.size() < 24 ){
                    throw std::runtime_error("Alphabet is too small to use predefined key.");
                }
                else{
                    key = { alph.at(21), alph.at(3), alph.at(7), alph.at(11), alph.at(23) };
                    std::cout << "(21, 3, 7, 11, 23) = " << key << std::endl;
                } 
            }
        }
        else {
            key = val_map.at("key");
        }

        if (key.empty()){
            throw std::runtime_error("Key is empty!");
        }

        // Select the algorithm
        crypto::text output;
        if (std::regex_match(algo, std::regex("vig.*")))
        {
            crypto::vigenere vigenere_cypher(alph);
            output = vigenere_cypher.encrypt(input_text, key);
        }
        else if (std::regex_match(algo, std::regex("auto.*")))
        {
            crypto::autokey_v2 autokey_cypher(alph);
            output = autokey_cypher.encrypt(input_text, key);
        }
        else {
            throw std::runtime_error("Unknown method of decryption (encryption)");
        }

        // Putting the result into output file
        crypto::file output_file(val_map.at("dest"), std::ios::out | std::ios::binary);
        output_file << output;

        std::cout << "Output was putted in \"" << val_map.at("dest") << "\"" << std::endl;
    }
    else if (method == "decrypt")
    {
        std::string algo = val_map.at("algo");

        // Set alphabet
        // Take it from *.json file
        crypto::file json_file(val_map.at("alph file"));
        crypto::alph alph = crypto::fdict(json_file).keys();

        //Set key
        crypto::key key;
        if ( val_map.at("key") == "" )
        {
            // If Vigenere use predefined key use predefined key (21, 3, 7, 11, 23)
            if ( std::regex_match(algo, std::regex("vig.*")) )
            {
                std::cout << "Using predefined key:\n";          
                if ( alph.size() < 24 ){
                    throw std::runtime_error("Alphabet is too small to use predefined key.");
                }
                else{
                    key = { alph.at(21), alph.at(3), alph.at(7), alph.at(11), alph.at(23) };
                    std::cout << "(21, 3, 7, 11, 23) = " << key << std::endl;
                } 
            }
        }
        else {
            key = val_map.at("key");
        }

        // Select the algorithm
        crypto::text output;
        if (std::regex_match(algo, std::regex("vig.*")))
        {
            if (key.empty()){
                throw std::runtime_error("Key is empty!");
            }

            crypto::vigenere vigenere_cypher(alph);
            output = vigenere_cypher.decrypt(input_text, key);
        }
        else if (std::regex_match(algo, std::regex("auto.*")))
        {
            crypto::autokey_v2 autokey_cypher(alph);

            // If key is empty generate length
            if (key.empty())
            {
                std::srand(std::time(nullptr)); 
                std::size_t key_size = 3 + std::rand() % 8;
                std::cout << "Key size = " << key_size << " was generated\n";
 
                output = autokey_cypher.decrypt(input_text, key_size);
            }
            else {
                output = autokey_cypher.decrypt(input_text, key);
            }
        }
        else {
            throw std::runtime_error("Unknown method of decryption (encryption)");
        }
    
        // Putting the result into output file
        crypto::file output_file(val_map.at("dest"), std::ios::out | std::ios::binary);
        output_file << output;

        std::cout << "Output was putted in \"" << val_map.at("dest") << "\"" << std::endl;
    }
    else if ( method == "friedman" ||
              method == "frequency" )
    {
        std::string key_size_field = val_map.at("key size");
        std::size_t key_size;

        // Using Kasiski method to set the key size
        if ( key_size_field == "" || key_size_field == "use kasiski" )
        {
            std::cout << "Using Kasiski method" << std::endl;
            std::cout << "\t" << "\"ngrams size\"\n\t" << "# ";
            std::getline(std::cin, key_size_field);

            std::size_t n = 3;
            if ( key_size_field == "" ){
                std::cout << "By default, using ngrams size = 3\n";
            }
            else {
                n = std::stoul(key_size_field);
            }

            key_size = crypto::algorithms::kasiski_method(input_text, n);
            std::cout << "Key size : " << key_size << std::endl;
        }
        else
        {
            key_size = std::stoul(key_size_field.c_str());
        }

        // Use alphabet from *.json file
        crypto::file  json_file(val_map.at("alph file"));
        crypto::fdict input_freqs = json_file;
        
        // Select the algorithm
        if (method == "friedman")
        {
            std::vector<crypto::key> keys = crypto::algorithms::friedman2_method(input_text, key_size, input_freqs.keys());

            crypto::file output_file(val_map.at("dest"), std::ios::out | std::ios::binary);
            output_file << keys;

            std::cout << "Keys was putted in \"" << val_map.at("dest") << "\"" << std::endl;
        }
        else{
            std::cout << "Key : " << crypto::algorithms::frequency_method(input_text, key_size, input_freqs) << std::endl;
        }
    }
    else if ( method == "kasiski" )
    {
        std::size_t n = 3;
        if ( val_map.at("ngrams size") == "" ){
            std::cout << "By default, using ngrams size = 3\n";
        }
        else {
            n = std::stoul(val_map.at("ngrams size"));
        }
        std::cout << "Key size : " << crypto::algorithms::kasiski_method(input_text, n) << std::endl;
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
parser::parse( const std::string &raw_line )
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

        std::cout << "\t" << *json_it << "\n";
        std::cout << "\t" << "# ";
        std::getline(std::cin, value);
        std::cout << "\n";

        retmap[*json_it] = value;
    }

    std::cout << std::endl;
    return retmap;
}

void
frontend::help()
{
    std::cout << "\tencrypt   - Encrypt file with Vigenere / Autokey v2 algorithm" << std::endl;
    std::cout << "\tdecrypt   - Decrypt file with Vigenere / Autokey v2 algorithm" << std::endl;
    std::cout << "\tfriedman  - Friedman Second method" << std::endl;
    std::cout << "\tfrequency - Apply frequency method to cypher" << std::endl;
    std::cout << "\tkasiski   - Search key size by using Kasiski method" << std::endl;
    std::cout << std::endl;
}
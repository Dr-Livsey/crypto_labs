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
                key = predefined_vigenere_key(alph);
                std::cout << "(21, 3, 7, 11, 23) = " << key << std::endl;
            }
            else if ( std::regex_match(algo, std::regex("auto.*")) )
            {
                key = get_encrypt_autokey(alph);
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
        crypto::fdict input_freqs = json_file;
        crypto::alph  alph = input_freqs.keys();

        //Set key
        crypto::key key;
        if ( val_map.at("key") == "" )
        {
            // If Vigenere use predefined key use predefined key (21, 3, 7, 11, 23)
            if ( std::regex_match(algo, std::regex("vig.*")) )
            {
                std::cout << "Using predefined key:\n";          
                key = predefined_vigenere_key(alph);
                std::cout << "(21, 3, 7, 11, 23) = " << key << std::endl;
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
            // If key is empty generate length
            if (key.empty())
            {
                autokey_break_the_cypher(input_freqs, input_text, val_map.at("dest"));
                return EXIT_SUCCESS;
            }
            else {
                output = crypto::autokey_v2(alph).decrypt(input_text, key);
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

void 
frontend::autokey_break_the_cypher( crypto::fdict &input_freqs, crypto::text &cypher, const std::string &dest)
{
    std::srand(std::time(nullptr)); 

    std::string user_input;
    std::size_t key_size;

    while ( user_input != "no")
    {
        // Generate key size
        key_size = (1 + std::rand() % 10);
        std::cout << "Key size = " << key_size << " was generated. ";

        // Decrypt with autokey and put it into dest file
        crypto::file output_file(dest, std::ios::out | std::ios::binary);
        output_file << crypto::autokey_v2(input_freqs.keys()).decrypt(cypher, key_size);

        std::cout << "Output was putted in \"" << dest << "\". Continue? (yes / no): "; output_file.close();
        std::getline(std::cin, user_input);
    }

    std::cout << "Using Frequency method with key size = " << key_size << ". ";
    std::cout << "Key = \""<< crypto::algorithms::frequency_method(cypher, key_size, input_freqs) << "\"" << std::endl;
}

crypto::key
frontend::get_encrypt_autokey( const crypto::alph &al )
{
    std::srand(std::time(nullptr)); 
    /*
     *  Generate key by key_size while we don't 
     *  obtain appropriate key (retval).
     */
    while (true)
    {
        std::string user_answer;
        crypto::key retval;

        // Generating key size and input the key
        std::size_t key_size = (1 + std::rand() % 10);
        std::cout << "Key size = " << key_size << " was generated. Enter the key: ";
        std::getline(std::cin, user_answer);

        /* Get first 'key_size' letters, which belongs to alphabet*/
        crypto::text text_key(user_answer);
            
        for ( auto it = text_key.cbegin(); it < text_key.cend() && retval.size() < key_size; it++)
        {
            if ( al.is_belongs({ *it }) == true ){
                retval += { *it };
            }
        }

        if ( retval.size() != key_size ){
            std::cout << " ( Exception ) Key does not fit to the key size. Try again." << std::endl;
        }
        else{
            std::cout << "The key is \"" << retval << "\"" << std::endl;  
            return retval;
        }
    }
    
    return crypto::key();
}

crypto::key 
frontend::predefined_vigenere_key( const crypto::alph &al )
{
    const std::size_t idx_arr[] = { 21, 3, 7, 11, 23 }; 
    crypto::key retval;

    for ( std::size_t i = 0; i < sizeof(idx_arr) / sizeof(std::size_t); i++ ){
        retval += { al.at(idx_arr[i] % al.size()) };
    }

    return retval;
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
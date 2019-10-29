#include <vector>
#include <string>
#include <map>

namespace crypto
{
    class key;
    class alph;
    class fdict;
    class text;
};

namespace frontend 
{
    namespace parser
    {
        using token     = std::string;
        using tokens    = std::vector<token>;
        using value_map = std::map<token, std::string>; 

        tokens    split( const std::string&, const std::string &delimiters = "\\s" );
        value_map parse( const std::string& );
    };

    /* 
     * Special cases for autokey_v2
     * get_encrypt_autokey      - Generate key length from 1 to 10 & wait user input
     * autokey_break_the_cypher - Generate key length from 1 to 10 & decrypt the cypher
     */
    crypto::key get_encrypt_autokey( const crypto::alph& );
    void        autokey_break_the_cypher( crypto::fdict &, crypto::text &, const std::string & );
    /*
     * Special case for Vigenere
     * Predefined key for Vigenere
     */
    crypto::key predefined_vigenere_key( const crypto::alph& );

    int run( void );
    int execute_command( const parser::value_map& );
    void help();
};
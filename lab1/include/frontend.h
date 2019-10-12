#include <vector>
#include <string>
#include <map>

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

    int run( void );
    int execute_command( const parser::value_map& );
    void help();
};
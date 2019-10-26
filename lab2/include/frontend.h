#include <vector>
#include <string>
#include <map>

namespace frontend 
{
    namespace parser
    {
        enum ptype{
            interactive,
            forward
        };

        using token     = std::string;
        using tokens    = std::vector<token>;
        using value_map = std::map<token, std::string>; 

        tokens    split( const std::string&, const std::string &delimiters = "\\s" );
        value_map parse( const std::string&, ptype t );
    };

    int run( void );
    int run(int argc, char *argv[]);

    int execute_command( const parser::value_map& );
    void help();
};
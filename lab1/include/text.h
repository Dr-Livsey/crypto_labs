#include <vector>
#include <set>
#include <map>

namespace crypto
{
    class file;

    using byte  = unsigned char;
    using fdict = std::map<byte, unsigned>; 
    
    class text : public std::vector<byte>
    {
    public:
        text( void ) : std::vector<byte>() {}
        text( file & );
        text( const std::initializer_list<byte> & );
        text( const std::string & );

        void from_file( file & );

        //void encrypt(algorithm *, key *);
        //void decrypt(algorithm *, key *);
    };

    fdict get_freq( const text& );
};

std::string byte_to_hex( const crypto::byte &b );

std::ostream& operator<<( std::ostream&, const crypto::text& );
std::ostream& operator<<( std::ostream&, const crypto::fdict& );
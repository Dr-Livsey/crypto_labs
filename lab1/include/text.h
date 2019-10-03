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
        text( const text::const_iterator &, const text::const_iterator & );
        text( const std::string & );

        void    from_file( file & );
        text    first_bytes( const std::size_t& ) const; 

        /* Concatanation of two texts */
        text& operator+=( const text & );
    };

    fdict get_freq( const text& );
};

std::string byte_to_hex( const crypto::byte &b );

std::ostream& operator<<( std::ostream&, const crypto::text& );
std::ostream& operator<<( std::ostream&, const crypto::fdict& );
#include <vector>
#include <string>

namespace crypto
{
    class file;

    using byte = unsigned char;
    
    class text : public std::vector<byte>
    {
    public:
        using slices    = std::vector<text>;
        using distances = std::vector<std::size_t>; 

        text( void ) : std::vector<byte>() {}
        text( file & );
        text( const std::initializer_list<byte> & );
        text( const text::const_iterator &, const text::const_iterator & );
        text( const std::string & );

        void        from_file( file & );
        text        first_bytes( const std::size_t& ) const; 

        const_iterator find( const text&, const std::size_t& n_pos = 0 ) const;
        distances      find_all( const text & ) const;

        slices      split( const std::size_t & ) const;
        slices      as_ngrams( const std::size_t &) const;

        /* Concatanation of two texts */
        text&       operator+=( const text & );
        text        operator+( const text & );
    };
};

std::string byte_to_hex( const crypto::byte &b );

std::ostream& operator<<( std::ostream&, const crypto::text& );
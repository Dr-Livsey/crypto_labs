#include "text.h"
#include "alph.h"

namespace crypto
{
    class fdict;
    
    struct key : public text
    {
        key( void ) : text() {}
        key( file &f ) : text(f) {}
        key( const text &t ) : text(t) {}
        key( const std::initializer_list<byte> &init_l ) : text(init_l) {}
        key( const std::string &s ) { this->assign(s.begin(), s.end()); }

        bool expand( std::size_t new_size );
    };

    struct cypher
    {
        cypher( const alph &init_al) : al(init_al) {}

        virtual text encrypt( const text &, const key& ) = 0;
        virtual text decrypt( const text &, const key& ) = 0;

        void set_alph( const alph & );
        alph get_alph( void ) const;

    protected:
        alph al;
    };

    struct vigenere : public cypher
    {
        vigenere( const alph &init_al) : cypher(init_al) {}

        text encrypt( const text&, const key& );
        text decrypt( const text&, const key& );
    };

    struct autokey_v2 : public cypher
    {
        autokey_v2( const alph &init_al) : cypher(init_al) {}

        text encrypt( const text&, const key& );
        text decrypt( const text&, const key& );
    };

    namespace algorithms
    {
        key frequency_method( const text&, const std::size_t&, const fdict& );

        std::vector<crypto::key> friedman2_method( const text&, const std::size_t&, const alph& );

        double get_mut_match_index( const text&, const text& );

        std::size_t kasiski_method( const text&, const std::size_t& n = 3 );
    };
};

std::ostream& 
operator<<( std::ostream& stream, const std::vector<crypto::key>& obj)
{
    for (auto i = obj.begin(); i != obj.end(); i++) 
    {
        stream << *i << std::endl;
    }
    return stream;
}
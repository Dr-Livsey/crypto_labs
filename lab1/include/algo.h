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

    struct algorithm
    {
        algorithm( const alph &init_al) : al(init_al) {}

        virtual text encrypt( const text &, const key& ) = 0;
        virtual text decrypt( const text &, const key& ) = 0;

        void set_alph( const alph & );
        alph get_alph( void ) const;

    protected:
        alph al;
    };

    struct vigenere : public algorithm
    {
        vigenere( const alph &init_al) : algorithm(init_al) {}

        text encrypt( const text&, const key& );
        text decrypt( const text&, const key& );
    };

    struct autokey_v2 : public algorithm
    {
        autokey_v2( const alph &init_al) : algorithm(init_al) {}

        text encrypt( const text&, const key& );
        text decrypt( const text&, const key& );

        /* Decrypts bytes after first 'key_size' */
        text decrypt( const text&, const std::size_t key_size );
    };

    key frequency_method( const text&, const std::size_t&, const fdict& );
};
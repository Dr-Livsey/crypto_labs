#include "block.h"

namespace crypto
{
    class file;
    class text;
};

namespace sp_cypher
{
    class subst;

    using base_key_t = std::bitset<KEY_SIZE>;

    struct key : public base_key_t
    {
        key( void ) : base_key_t() {}
        key( crypto::file & );
        key( crypto::text &t ) { from_text(t); }
        key( const std::string &s );
        key( const base_key_t &init_bitset ) : base_key_t(init_bitset) {}

        void from_text( crypto::text & );

        std::vector<key> expand() const;

        ~key() = default;
    };

    // Implementation of P = (9i + 5) mod 32 
    block p_transform ( const block & );
    block p_transform_inv (const block & );

    // SP-cyphering
    crypto::text encrypt( const key &, const crypto::text &, const subst & );
    crypto::text decrypt( const key &, const crypto::text &, const subst & );

};
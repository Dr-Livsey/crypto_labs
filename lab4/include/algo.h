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

    class counter
    {
    public:
        counter( crypto::file &f );

        counter& operator++(void);
        block    operator*();

        counter()  = default;
        ~counter() = default;
    
    private:
        block data;
    };

    // Implementation of P = (9i + 5) mod 32 
    block p_transform ( const block & );
    block p_transform_inv (const block & );

    // SP-cyphering
    namespace encrypt
    {
        crypto::text algo( const key &, const crypto::text &, const subst &, counter &cnt );

        block use_round( const block&, const key &, const subst &, std::size_t r_num = ROUNDS);
    };
    namespace decrypt
    {
        crypto::text algo( const key &, const crypto::text &, const subst &, counter &cnt );

        block use_round( const block&, const key &, const subst &, std::size_t r_num = ROUNDS);
    };
    

    void find_weak_keys( sp_cypher::subst &sub, crypto::file &dest );
    void error_prop( sp_cypher::subst &sub, crypto::file &dest);
};
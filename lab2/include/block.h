#include <bitset>
#include <vector>

namespace crypto
{
    class text;
};

namespace sp_cypher
{
    class key;

    /* Initial parameters (size in bits) */
    const std::size_t ROUNDS        = 4;    /* d = 4  */
    const std::size_t BLOCK_LEN     = 32;   /* n = 32 */
    const std::size_t KEY_SIZE      = BLOCK_LEN;
    const std::size_t SUBBLOCK_SIZE = 4;   /* m = 16 */

    /* Base class of block*/
    using block_base_t = std::bitset<BLOCK_LEN>;
    using subblock_t   = std::bitset<SUBBLOCK_SIZE>;

    class block : public block_base_t
    {
    public:
        using subblocks_t = std::vector<subblock_t>;

        block( void ) : block_base_t("") {}
        block( const block_base_t &b ) : block_base_t(b) {}
        block( const subblock_t & );
        block( unsigned n ) : block_base_t(n) {}
        block( crypto::text & );

        block  operator^( const key &);
        // block& operator+( const subblock_t &);

        subblocks_t  as_subblocks( void ) const;
        template< std::size_t subblock_s> std::vector<std::bitset<subblock_s>> as_subblocks( void ) const;

        crypto::text as_text( void ) const;
        ulong        as_ulong( void) const;

        ~block() = default;        
    };
};
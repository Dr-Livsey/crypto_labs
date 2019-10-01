#include <vector>
#include <ostream>

namespace crypto
{
    class text;

    using byte = unsigned char;

    class alph : public std::vector<byte> 
    {
        using containter = std::vector<byte>;

    public:
        alph( const text& );

        void from_text( const text& );

        byte direct_conv(byte i, byte j) const;
        byte reverse_conv(byte i, byte j) const;

        byte index( const byte& ) const;

        bool is_belongs( const std::vector<byte> &) const;
    };
};

std::ostream& operator<<( std::ostream&, const crypto::alph& );
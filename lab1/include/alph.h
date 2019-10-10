#include <vector>
#include <ostream>

namespace crypto
{
    class text;

    using byte = unsigned char;

    class alph : public std::vector<byte> 
    {
    public:

        using container = std::vector<byte>;

        enum conv_t{
            direct,
            reverse
        };

        alph( void ) : container() {}
        alph( const text& );

        void from_text( const text& );

        // Shift byte to offset value in alphabet
        byte left_shift( const byte&, const byte &offset ) const;
        byte right_shift( const byte&, const byte &offset ) const;

        byte direct_conv( byte i, byte j ) const;
        byte reverse_conv( byte i, byte j ) const;
        text vector_conv( const text &i, const text &j, conv_t conv_type );

        byte index( const byte& ) const;

        bool is_belongs( const std::vector<byte> &) const;
    };
};

std::ostream& operator<<( std::ostream&, const crypto::alph& );
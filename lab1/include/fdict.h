#include <map>
#include <vector>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace crypto
{
    class text;

    using byte = unsigned char;

    class fdict : public std::map<byte, double>
    {
    public:
        using pair_t        = std::pair<fdict::key_type, double>;
        using sorted_fvec_t = std::vector<pair_t>;

        fdict( const text& );
        fdict( void ) : std::map<byte, double>() {}

        static fdict get_freq( const text& );

        void from_text( const text& );

        // Represent std::map as json format
        nlohmann::json as_json( void ) const;
        // Sort dict by value
        sorted_fvec_t   as_sorted_vector( void ) const;
    };
};

std::ostream& operator<<( std::ostream&, const crypto::fdict& );
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace sp_cypher
{
    class block;
    /*
     *  Si substitution class.
     *  Map key - 'from' index
     *  Map val - 'to' index
     */

    using subst_bast_t = json;

    class subst : public subst_bast_t
    {
    public:

        block operator()( const block & ) const;
        subst operator~() const;

        subst()  = default;
        subst( const std::initializer_list<subst_bast_t::value_type> &init ) : subst_bast_t(init) {}
        subst( const std::string &json_file );

        ~subst() = default;
    };

};

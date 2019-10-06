#include "fdict.h"
#include "alph.h"
#include "text.h"
#include <sstream>
#include <iostream>


crypto::fdict::fdict( const text &t )
{
    from_text(t);
}

void 
crypto::fdict::from_text( const text &t )
{
    *this = get_freq(t);
}

json
crypto::fdict::as_json( void ) const
{
    if (this->empty()){
        return json({});
    }

    std::stringstream ss;
    ss << *this;

    return json::parse(ss.str());
}

crypto::fdict
crypto::fdict::get_freq( const text &t )
{
    fdict  retval;
    double text_size = static_cast<double>(t.size());

    for (auto c : t) retval[c] += 1.; 

    for ( auto it = retval.cbegin(); it != retval.cend(); it++)
    {
        retval[it->first] = it->second / text_size;
    }

    return retval;
}

crypto::fdict::sorted_fvec_t 
crypto::fdict::as_sorted_vector( void ) const
{
    //Put items from dictionary to vector
    sorted_fvec_t freq_vector(this->cbegin(), this->cend());

    // Sort frequences by value
    std::sort(freq_vector.begin(), freq_vector.end(), []( const fdict::pair_t &a, const fdict::pair_t &b) -> bool
    {
        return a.second < b.second;
    });

    return freq_vector;
}

crypto::alph
crypto::fdict::keys( void ) const
{
    alph keys;
    for ( auto p : *this ){
        keys.push_back(p.first);
    }
    return keys;
}

crypto::fdict::pair_t
crypto::fdict::get_most_frequent( void ) const
{
    if (this->empty())
        return pair_t();

    return this->as_sorted_vector().back();
}

std::ostream& 
operator<<( std::ostream& stream, const crypto::fdict& obj)
{
    json freq_dict;

    for (auto i = obj.begin(); i != obj.end(); i++) 
    {
        std::string byte_str = byte_to_hex(i->first);

        std::stringstream ss;

        if (i->first == '\n'){ 
            ss << "\\n";
        }
        else if (i->first == '\r'){
            ss << "\\r";
        }
        else if (i->first == '\t'){
            ss << "\\t";
        }
        else{
            ss << i->first;
        }

        freq_dict[byte_str] = {{ "ASCII char", ss.str() }, { "value", i->second }};
    }

    stream << freq_dict.dump(4);

    return stream;
}
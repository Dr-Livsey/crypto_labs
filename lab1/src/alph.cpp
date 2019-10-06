#include "alph.h"
#include "text.h"
#include <algorithm>

crypto::alph::alph( const text &init_t ) : container(init_t)
{
    from_text(init_t);
}

crypto::byte
crypto::alph::index( const byte &value ) const
{
    auto pos = std::find(begin(), end(), value);

    if (pos == end()){
        std::string what = "Byte \'" + byte_to_hex(value) + "\' not found in alph";
        throw std::out_of_range(what);
    }

    return static_cast<byte>(pos - begin());
}

void
crypto::alph::from_text( const text &init_t )
{
    this->assign(init_t.begin(), init_t.end());
    std::sort(this->begin(), this->end());

    // remove duplicates
    erase(std::unique(this->begin(), this->end()), this->end());
}

crypto::byte
crypto::alph::direct_conv(byte plain_byte, byte key_byte) const
{
    return this->at(((int)index(plain_byte) + index(key_byte)) % size());
}

crypto::byte
crypto::alph::reverse_conv(byte key_byte, byte cypher_byte) const
{
    return this->at(((int)index(cypher_byte) - index(key_byte) + size()) % size());
}

crypto::text 
crypto::alph::vector_conv(const text &i, const text &j, conv_t conv_type)
{
    text result;

    for (std::size_t idx = 0; idx < std::min(i.size(), j.size()); idx++)
    {
        byte cur = (conv_type == conv_t::direct) ? direct_conv(i.at(idx), j.at(idx)) \
                                                 : reverse_conv(i.at(idx), j.at(idx));
        result.push_back(cur);
    }

    return result;
}

bool
crypto::alph::is_belongs( const std::vector<byte> &vec ) const
{
    for ( auto b : vec ){
        if (std::binary_search(begin(), end(), b) == false){
            return false;
        }
    }
    return true;
}

std::ostream& operator<<( std::ostream& stream, const crypto::alph& obj)
{
    if (obj.empty())
        return stream;

    stream << "{ ";
    for (auto i = obj.begin(); i != obj.end(); i++) 
    {
        stream << byte_to_hex(*i) << "\"" << *i << "\"" << ", ";
    }
    stream << "\b\b }";
    return stream;
}
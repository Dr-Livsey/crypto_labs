#include "algo.h"
#include <iostream>
#include <algorithm>


crypto::text
crypto::vigenere::encrypt( 
    const text &plain_text, const key &k)
{
    if (al.is_belongs(k) == false){
        throw std::runtime_error("Key is not belongs to alphabet!");
    }
    if (plain_text.empty()){
        throw std::runtime_error("Plain text is empty!");
    }
    if (k.empty()){
        throw std::runtime_error("Key is empty!");
    }
    if (al.empty()){
        throw std::runtime_error("Alph is empty!");
    }

    // Plain text size
    std::size_t pt_size = plain_text.size();

    // Expand key
    key  ext_k = k;
    ext_k.expand(pt_size);

    return al.vector_conv(plain_text, ext_k, alph::conv_t::direct);
}

crypto::text
crypto::vigenere::decrypt( 
    const text &cypher_text, const key &k)
{
    if (al.is_belongs(k) == false){
        throw std::runtime_error("Key is not belongs to alphabet!");
    }
    if (cypher_text.empty()){
        throw std::runtime_error("Cypher text is empty!");
    }
    if (k.empty()){
        throw std::runtime_error("Key is empty!");
    }
    if (al.empty()){
        throw std::runtime_error("Alph is empty!");
    }

    // Cypher text size
    std::size_t ct_size = cypher_text.size();

    // Expand key
    key  ext_k = k;
    ext_k.expand(ct_size);

    return al.vector_conv(ext_k, cypher_text, alph::conv_t::reverse);
}

crypto::text
crypto::autokey_v2::encrypt(
    const text &plain_text, const key &key)
{
    std::size_t key_size = key.size();
    crypto::key cur_key       = key;
    text        cypher;

    vigenere vigenere_cypher(this->al);

    for (auto pt_iter = plain_text.cbegin(); pt_iter != plain_text.cend(); /**/)
    {
        /* 
            Remaining unencrypted length of plain text.
        */
        std::size_t rem_len =  static_cast<std::size_t>(plain_text.cend() - pt_iter);
        /* 
           Size of chunk is the min of remaining length 
           and key size.
        */
        std::size_t size_of_chunk = std::min(rem_len, key_size);

        text pt_chunk(pt_iter, pt_iter + size_of_chunk);

        cur_key  = vigenere_cypher.encrypt(pt_chunk, cur_key);
        cypher  += cur_key;
        pt_iter += size_of_chunk;
    }

    return cypher;
}

crypto::text
crypto::autokey_v2::decrypt(
    const text &cypher_text, const key &key)
{
    std::size_t key_size = key.size();
    text        plain_text;

    plain_text += al.vector_conv(key, cypher_text, alph::conv_t::reverse);

    if (key_size < cypher_text.size())
    {
        plain_text += this->decrypt(cypher_text, key.size());
    }

    return plain_text;
}

crypto::text
crypto::autokey_v2::decrypt(
    const text &cypher_text, const std::size_t key_size)
{
    text plain_text;

    if (key_size >= cypher_text.size())
        throw  std::runtime_error("Key size >= Cypher text size");

    for (auto c_iter = cypher_text.cbegin(); c_iter != cypher_text.cend() - key_size; c_iter++)
    {
        plain_text += { al.reverse_conv(*c_iter, *(c_iter + key_size)) };
    }

    return plain_text;
}

bool
crypto::key::expand( std::size_t new_size )
{
    if (this->empty())
        throw std::runtime_error("Key is empty!");

    std::size_t start_size = this->size();

    bool status = (new_size >= start_size) ? true : false;

    if (status == false){
        return false;
    }
    else if (new_size == start_size) {
        return true; 
    }

    key acc = *this;
    std::size_t excess = ((new_size / start_size) + 1) * start_size - new_size;

    for (std::size_t  i = 0; i < (new_size / start_size); i++){
        insert(end(), acc.begin(), acc.end());
    }

    this->resize(this->size() - excess);

    return true;
}

void
crypto::algorithm::set_alph( const alph &new_al)
{
    this->al = new_al;
}

crypto::alph
crypto::algorithm::get_alph( void ) const
{
    return this->al;
}
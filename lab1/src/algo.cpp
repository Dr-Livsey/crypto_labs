#include "algo.h"
#include <iostream>


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

    text cypher_text;
    cypher_text.resize(pt_size);

    for (std::size_t i = 0; i < pt_size; i++)
    {
        if (al.is_belongs({ plain_text[i] }) == false){
            throw std::runtime_error("Byte '" + byte_to_hex(plain_text[i]) + "' is not belongs to alphabet!");
        }

        cypher_text[i] = al.direct_conv(plain_text[i], ext_k[i]);
    }    

    return cypher_text;
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

    text plain_text;
    plain_text.resize(ct_size);

    for (std::size_t i = 0; i < ct_size; i++)
    {
        if (al.is_belongs({ cypher_text[i] }) == false){
            throw std::runtime_error("Byte '" + byte_to_hex(plain_text[i]) + "' is not belongs to alphabet!");
        }
        
        plain_text[i] = al.reverse_conv(ext_k[i], cypher_text[i]);
    }    

    return plain_text;
}

// crypto::text
// crypto::autokey_v2::encrypt(
//     const text &plain_text, const key &k)
// {
//     vigenere vig_obj(al);

//     key new_key(vig_obj.encrypt(plain_text, k));
// }

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
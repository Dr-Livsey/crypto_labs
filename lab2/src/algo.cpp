#include "algo.h"
#include "file.h"
#include "text.h"
#include "subst.h"

#include <iostream>

using namespace sp_cypher;

key::key( crypto::file &f )
{
    crypto::text key_text = f;
    from_text(key_text);
}

key::key( const std::string &s )
{
    crypto::text key_text;
    key_text.assign(s.begin(), s.end());
    from_text(key_text);
}

void
key::from_text( crypto::text &key_text )
{
    // Check size in bits
    if ( key_text.size() > (KEY_SIZE / 8) )
        throw std::runtime_error("key(): Key size must be <= " + std::to_string(KEY_SIZE / 8) + " bytes");

    this->reset();

    for ( auto it = key_text.rbegin(); it < key_text.rend(); it++ )
    {
        *this <<= sizeof(crypto::byte) * 8;
        *this |= base_key_t(*it);
    }
}

std::vector<key>
key::expand( void ) const
{
    std::vector<key> round_keys = { *this, ~(*this), *this, ~(*this) };

    if ( size() != ROUNDS )
        throw std::runtime_error("expand(): Amount of round keys != " + std::to_string(ROUNDS));

    // Hardcoded expansion
    return { *this, ~(*this), *this, ~(*this) };
}

/*
 * P = (9i + 5) mod BLOCK_LEN 
 */
block sp_cypher::p_transform ( const block &b )
{
    block result;
    for ( std::size_t i = 0; i < b.size(); i++ ){
        result[i] = b[ (9*i + 5) % BLOCK_LEN];
    }
    return result;
}
/*
 * P = 25*(i - 5) mod BLOCK_LEN
 */
block sp_cypher::p_transform_inv (const block &b )
{
    block result;
    for ( std::size_t i = 0; i < b.size(); i++ ){
        result[ (9*i + 5) % BLOCK_LEN] = b[i];
    }
    return result;
}

/*
 * SP-cypher encryption function
 */
crypto::text
encrypt( const key &k, const crypto::text &plain_text, const subst &sub )
{
    if ( BLOCK_LEN % SUBBLOCK_SIZE != 0 )
        throw std::runtime_error("^(): BLOCK_LEN % SUBBLOCK_SIZE must be equal to 0");

    crypto::text cypher_text;
    block cur_block;

    for ( crypto::text slice : plain_text.split(BLOCK_LEN / 8) )
    {
        cur_block = block(slice);

        // Go to rounds
        for ( auto round_key : k.expand() )
        {
            /*
             * 1. XOR current block with round key
             */ 
            cur_block = cur_block ^ round_key;
            /*
             * 2. Split block into subblocks
             * 3. For each subblock use S-substitution
             */ 
            block sub_cur_block;
            for ( auto subblock : cur_block.as_subblocks(SUBBLOCK_SIZE) )
            {
                sub_cur_block <<= SUBBLOCK_SIZE;
                sub_cur_block |= sub(block(subblock));
            }
            /*
             * 4. Use P-transorm function
             */
            cur_block = p_transform(sub_cur_block);
        }

        // Add enrypted block to cypher text 
        cypher_text += cur_block.as_text();
    }

    return cypher_text;
}
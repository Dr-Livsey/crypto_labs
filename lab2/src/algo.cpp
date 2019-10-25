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

    if ( round_keys.size() != ROUNDS )
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
sp_cypher::encrypt( const key &k, const crypto::text &plain_text, const subst &sub )
{
    if ( BLOCK_LEN % SUBBLOCK_SIZE != 0 )
        throw std::runtime_error("^(): BLOCK_LEN % SUBBLOCK_SIZE must be equal to 0");

    if ( plain_text.empty() ) 
        return crypto::text();

    // Block size in bytes
    const std::size_t block_len_bytes = BLOCK_LEN / 8;

    // Key expansion
    std::vector<key> round_keys = k.expand();

    // Divide plain text into slices
    crypto::text::slices ptext_slices   = plain_text.split(block_len_bytes);
 
    // Add excess block with size of last text slice
    block excess_block(block_len_bytes - ptext_slices.back().size());
    ptext_slices.push_back(excess_block.as_text());

    std::size_t ptext_slices_s = ptext_slices.size();

    crypto::text cypher_text;

    // Print loading line if need
    std::size_t loading_parts = ptext_slices_s / 20;
    if (loading_parts > 1)
    {
        std::cout << "                    " << std::flush;
        std::cout << "                      ]\rEncryption process: [" << std::flush;
    }
    /*
     * Iterate throught text slices
     */
    for ( std::size_t i = 0; i < ptext_slices_s; i++ )
    {
        block cur_block = block(ptext_slices.at(i));

        // Go to rounds
        for ( auto round_key : round_keys )
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

        // 5. Use whitening
        cur_block = cur_block ^ key(0xffffffff);

        // Add enrypted block to cypher text 
        cypher_text += cur_block.as_text();

        // Only for loading info
        if ( i && loading_parts > 1 && i % loading_parts == 0 ) std::cout << "#" << std::flush;
    }

    std::cout << std::endl;
    return cypher_text;
}

/*
 * SP-cypher decryption function
 */
crypto::text
sp_cypher::decrypt( const key &k, const crypto::text &cypher_text, const subst &sub )
{
    if ( BLOCK_LEN % SUBBLOCK_SIZE != 0 )
        throw std::runtime_error("^(): BLOCK_LEN % SUBBLOCK_SIZE must be equal to 0");

    if ( cypher_text.empty() ) 
        return crypto::text();

    // Block size in bytes
    const std::size_t block_len_bytes = BLOCK_LEN / 8;

    // Key expansion
    std::vector<key> round_keys = k.expand();

    // Divide cypher text into slices
    crypto::text::slices ctext_slices   = cypher_text.split(BLOCK_LEN / 8);
    std::size_t          ctext_slices_s = ctext_slices.size();

    // Inverse S-substitution
    subst inv_sub = ~sub;

    crypto::text plain_text;

    // Print loading line if need
    std::size_t loading_parts = ctext_slices_s / 20;
    if (loading_parts > 1)
    {
        std::cout << "                    " << std::flush;
        std::cout << "                      ]\rDecryption process: [" << std::flush;
    }
    /*
     * Iterate throught text slices
     */
    for ( std::size_t i = 0; i < ctext_slices_s; i++ )
    {
        block cur_block = block(ctext_slices.at(i));
        /*
         * Use whitening
         */
        cur_block = cur_block ^ key(0xffffffff);

        // Go to rounds in reverse order
        for ( auto round_key_it = round_keys.rbegin(); round_key_it < round_keys.rend(); round_key_it++ )
        {
            /*
             * 1. Use inverse P-transorm function
             */
            cur_block = p_transform_inv(cur_block);
            /*
             * 2. Split block into subblocks
             * 3. For each subblock use inverse S-substitution
             */ 
            block sub_cur_block;
            for ( auto subblock : cur_block.as_subblocks(SUBBLOCK_SIZE) )
            {
                sub_cur_block <<= SUBBLOCK_SIZE;
                sub_cur_block |= inv_sub(block(subblock));
            }
            /*
             * 4. XOR current block with round key
             */ 
            cur_block = sub_cur_block ^ (*round_key_it);
        }

        // Add decrypted block to plain text 
        plain_text += cur_block.as_text();

        // Only for loading info
        if ( i && loading_parts > 1 && i % loading_parts == 0 ) std::cout << "#" << std::flush;
    }
    /*
     * Delete excess zeroes if exist
     */
    crypto::text excess_block_txt(plain_text.end() - block_len_bytes, plain_text.end());

    ulong excess_zeroes = block(excess_block_txt).as_ulong();

    plain_text.erase(plain_text.end() - (block_len_bytes + excess_zeroes), plain_text.end());

    std::cout << std::endl;
    return plain_text;
}
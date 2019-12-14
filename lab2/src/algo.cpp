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
    return round_keys;
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
 ! SP-cypher encryption round
 * @r_num - amount of rounds to be used. By default, this value is equal to ROUNDS
 */
sp_cypher::block
sp_cypher::encrypt::use_round( const block &b, const key &k, const subst &sub, std::size_t r_num)
{
    if (r_num == 0) return b;

    auto key_exp = k.expand();

    if ( r_num > key_exp.size() ){
        throw std::runtime_error("Amounts of rounds must be <= round keys");
    }

    block cur_block = b;
    for ( std::size_t i = 0; i < r_num; i++ )
    {
        /*
        * 1. XOR current block with round key
        */ 
        block xor_block = cur_block ^ key_exp.at(i);
        /*
        * 2. Split block into subblocks
        * 3. For each subblock use S-substitution
        */ 
        block sub_block;
        auto  subblocks = xor_block.as_subblocks();

        for ( auto s = subblocks.rbegin(); s < subblocks.rend(); s++ )
        {
            sub_block <<= SUBBLOCK_SIZE;
            sub_block |= sub(*s);
        }
        /*
        * 4. Use P-transorm function
        */
        cur_block = p_transform(sub_block);
    }

    return cur_block;
}
/*
 ! SP-cypher decryption round
 * @r_num - amount of rounds to be used. By default, this value is equal to ROUNDS
 */
sp_cypher::block
sp_cypher::decrypt::use_round( const block &b, const key &k, const subst &inv_sub, std::size_t r_num)
{
    if (r_num == 0) return b;

    auto key_exp = k.expand();

    if ( r_num > key_exp.size() ){
        throw std::runtime_error("Amounts of rounds must be <= round keys");
    }

    block cur_block = b;
    std::size_t   i = 0;

    for ( auto round_key = key_exp.rbegin() + (key_exp.size() - r_num); i < r_num ; round_key++, i++ )
    {
        /*
         * 1. Use inverse P-transorm function
         * 2. Split block into subblocks
         * 3. For each subblock use inverse S-substitution
         */ 
        block sub_block;
        auto  subblocks = p_transform_inv(cur_block).as_subblocks();

        for ( auto s = subblocks.rbegin(); s < subblocks.rend(); s++ )
        {
            sub_block <<= SUBBLOCK_SIZE;
            sub_block |= inv_sub(*s);
        }
        cur_block = sub_block ^ *round_key;
    }
    
    return cur_block;
}

/*
 ! SP-cypher encryption function
 */
crypto::text
sp_cypher::encrypt::algo( const key &k, const crypto::text &plain_text, const subst &sub )
{
    if ( BLOCK_LEN % SUBBLOCK_SIZE != 0 )
        throw std::runtime_error("^(): BLOCK_LEN % SUBBLOCK_SIZE must be equal to 0");

    if ( plain_text.empty() ) 
        return crypto::text();

    // Block size in bytes
    const std::size_t block_len_bytes = BLOCK_LEN / 8;

    // Divide plain text into slices
    crypto::text::slices ptext_slices   = plain_text.split(block_len_bytes);
 
    // if (plain_text.size() % block_len_bytes != 0)
    // {
        // Add excess block with size of last text slice
        block excess_block(ptext_slices.back().size());
        ptext_slices.push_back(excess_block.as_text());
    // }

    std::size_t ptext_slices_s = ptext_slices.size();

    crypto::text cypher_text;

    // Print loading line if need
    bool print_endl = false;
    std::size_t loading_parts = ptext_slices_s / 20;
    if (loading_parts > 1)
    {
        print_endl = true;
        std::cout << "                    " << std::flush;
        std::cout << "                      ]\rEncryption process: [" << std::flush;
    }
    /*
     * Iterate throught text slices
     */
    for ( std::size_t i = 0; i < ptext_slices_s; i++ )
    {
        block cur_block  = block(ptext_slices.at(i));
        block encr_block = use_round(cur_block, k, sub) ^ key(0xffffffff);

        // Add enrypted block to cypher text 
        cypher_text += encr_block.as_text();

        // Only for loading info
        if ( i && loading_parts > 1 && i % loading_parts == 0 ) std::cout << "#" << std::flush;
    }

    if ( print_endl == true ) std::cout << std::endl;
    return cypher_text;
}

/*
 ! SP-cypher decryption function
 */
crypto::text
sp_cypher::decrypt::algo( const key &k, const crypto::text &cypher_text, const subst &sub )
{
    if ( BLOCK_LEN % SUBBLOCK_SIZE != 0 )
        throw std::runtime_error("^(): BLOCK_LEN % SUBBLOCK_SIZE must be equal to 0");

    if ( cypher_text.empty() ) 
        return crypto::text();

    // Block size in bytes
    const std::size_t block_len_bytes = BLOCK_LEN / 8;

    // Divide cypher text into slices
    crypto::text::slices ctext_slices   = cypher_text.split(BLOCK_LEN / 8);
    std::size_t          ctext_slices_s = ctext_slices.size();

    // Inverse S-substitution
    subst inv_sub = ~sub;

    crypto::text plain_text;

    // Print loading line if need
    bool print_endl = false;
    std::size_t loading_parts = ctext_slices_s / 20;
    if (loading_parts > 1)
    {
        print_endl = true;
        std::cout << "                    " << std::flush;
        std::cout << "                      ]\rDecryption process: [" << std::flush;
    }
    /*
     * Iterate throught text slices
     */
    for ( std::size_t i = 0; i < ctext_slices_s; i++ )
    {
        block cur_block = block(ctext_slices.at(i)) ^ key(0xffffffff);

        // Add decrypted block to plain text 
        plain_text += use_round(cur_block, k, inv_sub).as_text();

        // Only for loading info
        if ( i && loading_parts > 1 && i % loading_parts == 0 ) std::cout << "#" << std::flush;
    }
    /*
     * Delete excess zeroes if exist
     */
    {
        // Get last block
        crypto::text excess_block_txt(plain_text.end() - block_len_bytes, plain_text.end());

        // Convert it to number
        ulong excess_block_s = block(excess_block_txt).to_ulong();

        if (excess_block_s <= block_len_bytes)
        {
            plain_text.erase(plain_text.end() - (2 * block_len_bytes - excess_block_s), plain_text.end());
        }
    }

    if ( print_endl == true ) std::cout << std::endl;
    return plain_text;
}

void
sp_cypher::find_weak_keys( sp_cypher::subst &sub, crypto::file &dest )
{
    /*
     * Already found:
     * 248384847
     * 794251893
     */

    const std::size_t key_max = 0xffffffff;

    crypto::text    test_text  = {'a', 'b', 'c', 'd' };
    block           test_block(test_text);

    // Create loading line
    std::size_t loading_parts = key_max / 100;

    for ( std::size_t i = 1073741800; i <= key_max; i++)
    {
        key cur_key(i);

        block fst_enc = encrypt::use_round(test_block,  cur_key, sub);
        block sec_enc = encrypt::use_round(fst_enc,     cur_key, sub);

        if ( fst_enc == sec_enc ){
            dest << i << std::endl;
        }

        if ( i % loading_parts == 0 ) std::cout << i << std::flush;
    }

    std::cout << std::endl;
}

void 
sp_cypher::error_prop( sp_cypher::subst &sub, crypto::file &dest )
{
    key test_key(783782231);

    for (std::size_t rounds_am = 1; rounds_am <= 4; rounds_am++)
    {
        dest << "Round: " << rounds_am << std::endl;

        bool round_step = true;
        for (std::size_t offset = 0; offset < 32; offset++)
        {
            dest << "\tOffset: " << offset << " -> " << std::flush;

            std::size_t acc = 0, prev_acc = 0;
            // Amount of times that 'acc' equal to previous iteration 
            std::size_t same_count = 1000000;
            
            bool offset_step = false;
            for (std::size_t test_value = 0; test_value <= 0xffffffff; test_value++)
            {
                block set_bit(test_value);
                block zero_bit(test_value);

                set_bit[offset]  = true;
                zero_bit[offset] = false;

                block encr_block_1 = encrypt::use_round(set_bit, test_key, sub, rounds_am);
                block encr_block_0 = encrypt::use_round(zero_bit, test_key, sub, rounds_am);

                acc |= (encr_block_1.to_ulong() ^ encr_block_0.to_ulong());

                std::cout << block(acc) << std::endl;

                same_count = (acc == prev_acc) ? same_count - 1 : same_count;

                if (acc == 0xffffffff)
                {
                    offset_step = true;
                    break;
                }
                else if (!same_count) break;

                prev_acc = acc;
            }

            if (!offset_step)
            {
                dest << "False" << std::endl;
                round_step = false;
                break;
            }
            else {
                dest << "True" << std::endl;
            }
        }
        dest << "\tError propagation is ";
        dest << ((round_step == true) ? "FOUND\n" : "NOT FOUND\n") << std::endl;

        if (round_step == true){
            break;
        }
    }
}
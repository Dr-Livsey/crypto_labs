#include "algo.h"
#include "text.h"
#include <string>
#include <iostream>
#include <algorithm>

using namespace sp_cypher;

block::block( crypto::text &block_text )
{
    if ( block_text.size() > (BLOCK_LEN / 8) )
        throw std::runtime_error("block(): Block size must be <= " + std::to_string(BLOCK_LEN / 8) + " bytes"); 

    this->reset();

    for ( auto it = block_text.rbegin(); it < block_text.rend(); it++ )
    {
        *this <<= sizeof(crypto::byte) * 8;
        *this |= block_base_t(*it);
    }
}

block::block( const subblock_t &subblock ) 
    : block_base_t(subblock.to_string()) 
{
    /**/
}

/*
 * @param subblock_s - each size of subblock in bits
 */
block::subblocks_t
block::as_subblocks( void ) const
{
    return this->as_subblocks<SUBBLOCK_SIZE>();
}

template<std::size_t subblock_s> std::vector<std::bitset<subblock_s>>
block::as_subblocks(void) const
{
    if ( BLOCK_LEN % SUBBLOCK_SIZE != 0 )
        throw std::runtime_error("^(): (BLOCK_LEN % subblock_s) must be equal to 0");

    std::vector<std::bitset<subblock_s>> retval;

    std::string bstr = to_string();
    std::size_t chunk_size = subblock_s;

    for ( auto i = bstr.rbegin(); i < bstr.rend(); i += chunk_size )
    {
        std::size_t tail_size  = static_cast<std::size_t>(bstr.rend() - i);
        chunk_size = std::min(subblock_s, tail_size);

        // Construct new subblock on the top of vector
        std::string reversed_bstr(i, i + chunk_size);
        std::reverse(reversed_bstr.begin(), reversed_bstr.end());

        retval.emplace_back(reversed_bstr);
    }

    return retval; 
}

block
block::operator^( const key &k)
{
    if ( BLOCK_LEN != KEY_SIZE )
        throw std::runtime_error("^(): BLOCK_LEN must be equal to KEY_SIZE");

    block_base_t this_as_block = block_base_t(to_string());
    block_base_t key_as_block = block_base_t(k.to_string());

    return this_as_block ^ key_as_block;
}

crypto::text
block::as_text( void ) const
{
    crypto::text result;

    for ( auto subblock : this->as_subblocks<8>()){
        result += { static_cast<crypto::byte>(std::stoul(subblock.to_string(), nullptr, 2)) };
    }

    return result;
}
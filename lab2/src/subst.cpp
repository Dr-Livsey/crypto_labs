#include "subst.h"
#include "block.h"

#include <algorithm>
#include <fstream>

using namespace sp_cypher;

subst::subst( const std::string &json_file )
{
    std::ifstream fd(json_file);

    if (fd.is_open() == false){
        throw std::runtime_error("Filed to open ifstream. File: " + json_file);
    }

    fd >> *this;
    fd.close();

    std::sort(begin(), end());
}

/*
 * Composition with block
 */
block 
subst::operator()( const block &b ) const
{
    block result_block = b;

    // Check sizes of arguments
    if ( b.size() < this->size() ) {
        throw std::runtime_error("subst() : Block size must be >= Subst. size");
    }

    for ( auto spair : *this )
    {
        unsigned from_index = spair.at(0);
        unsigned to_index   = spair.at(1);

        result_block[from_index] = b[to_index];
    }

    return result_block;
}
/* 
 * Find inverse substitution.
 */
subst 
subst::operator~( void ) const
{
    subst inv_subst = json::array();

    for ( auto spair : *this )
    {
        unsigned index = spair.at(0);
        unsigned value = spair.at(1);
        inv_subst.push_back({value, index});
    }

    std::sort(inv_subst.begin(), inv_subst.end());

    return inv_subst;
}
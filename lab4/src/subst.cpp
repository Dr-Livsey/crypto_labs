#include "subst.h"
#include "block.h"

#include <algorithm>
#include <fstream>
#include <iostream>

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
    return block(this->at(b.to_ulong()).at(1).get<unsigned>());
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
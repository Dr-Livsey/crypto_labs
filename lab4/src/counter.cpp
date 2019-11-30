#include "file.h"
#include "text.h"
#include "algo.h"

using namespace sp_cypher;

counter::counter( crypto::file &f ) 
{
    crypto::text init_vector = f;
    data = block(init_vector);
}

counter& 
counter::operator++(void)
{
    data = block(static_cast<unsigned>(3*(data.to_ulong() + 1)));
    return *this;
}

block 
counter::operator*()
{
    return data;
}
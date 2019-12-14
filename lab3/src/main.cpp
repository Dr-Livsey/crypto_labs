#include "algo.h"
#include "subst.h"
#include "text.h"
#include "file.h"

#include <iostream>
#include <vector>
#include <stdlib.h>

unsigned cycle_shift(unsigned long b, int n)
{
    unsigned LBIT = 0x80000000;
    //unsigned RBIT = 0x00000001;
    int counter;

    if (n >= 0)
    {
        /* left shift */
        for (counter = 0; counter < n ;counter++)
        {
            if (LBIT & b)
            {
                b <<= 1;
                b |= 1;
            }
            else
                b <<= 1;
        }
    }
    else
    {
        /* right shift */
        // for (counter = 0; counter < n ;counter++)
        // {
        //     if (RBIT & b)
        //     {
        //         b >>= 1;
        //         b += 128;
        //     }
        //     else
        //         b >>= 1;
        // }
    }

    return static_cast<unsigned>(b);
}

void simple_relations()
{
    using namespace sp_cypher;

    block test_text(0xdeadbeef);
    key   test_key(0x18723612);

    subst sub("src/sub.json");

    auto encr = encrypt::use_round(test_text, test_key, sub);

    for (std::size_t g2 = 1; g2 < 32; g2++)
    {
        for (std::size_t h = 0; h < 32; h++)
        {
            for (std::size_t g1 = 0; g1 < 32; g1++)
            {
                // 1. g1(X)
                block g1X  = block(cycle_shift(test_text.to_ulong(), g1));
                // 2. h(key)
                key   hkey = key(cycle_shift(test_key.to_ulong(), h));
                // 3. Y = F_h(key)_(g1(X))
                block Y = encrypt::use_round(g1X, hkey, sub);
                // 4. g2Y
                block g2Y = block(cycle_shift(Y.to_ulong(), g2));

                if (g2Y == encr){
                    std::cout << "g1 = " << g1 << "; g2 = " << g2 << "; h = " << h << std::endl;
                }
            }
        }
    }
}

void brute_force(sp_cypher::block &X, sp_cypher::block &Y1, sp_cypher::block &g1Y2 )
{
    using namespace sp_cypher;

    subst sub("src/sub.json");

    Y1   = Y1.to_ulong()    ^ 0xffffffff;
    g1Y2 = g1Y2.to_ulong()  ^ 0xffffffff; 

    auto Y2 = block(cycle_shift(g1Y2.to_ulong(), 16));

    for (std::size_t i = 0; i <= 0xffffffff; i++)
    {
        key cur_key(i);

        auto Y = encrypt::use_round(X, cur_key, sub);

        std::cout << std::hex << i << std::endl;

        if ( Y == Y1 )
        {
            std::cout << "Key: [ 0x"  << std::hex << i << " ]" << std::endl;
            break;
        }
        else if ( Y == Y2 )
        {
            std::cout << "Key: [ 0x" << std::hex << cycle_shift(i, 16) << " ]" << std::endl;
            break;
        }  
    }
}

int main( void )
{
    using namespace sp_cypher;

    crypto::file X_file("X.txt");
    crypto::file Y_file("Y.txt");

    crypto::file g1Y_file("g1Y.txt");

    auto X_text     = crypto::text(X_file).split(BLOCK_LEN / 8);
    auto Y_text     = crypto::text(Y_file).split(BLOCK_LEN / 8);
    auto g1Y_text   = crypto::text(g1Y_file).split(BLOCK_LEN / 8);

    block X_block     = X_text.at(0);
    block Y_block     = Y_text.at(0);
    block g1Y_block   = g1Y_text.at(0);

    brute_force(X_block, Y_block, g1Y_block);
    return 0;
}
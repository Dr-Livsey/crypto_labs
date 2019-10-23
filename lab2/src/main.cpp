#include <iostream>
#include "subst.h"
#include "file.h"
#include "algo.h"
#include "text.h"

/* 
 * SP cyphering + whitening
 * d = 4
 * m = 4
 * teta = K = B = { 0, 1 }^32 - length of the key 32
 * RoundKeys + 1 = ( teta, |teta, teta, |teta, 1^32 )
 ! Si = ( 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 )
 ! P  = (9i + 5) mod 32 
 * 
*/

/*
 * TODO:
 *  1. round_keys ( key : {0,1}^32) -> [ key, ~key, key, ~key, 1^32 ]
 *  2. s_subst ( block : {0, 1}^16) -> S-substitusion result
 *  3. p_transform ( block : {0, 1}^32) -> P-substitution result
 *  4.  
 */

int main() 
{
    using namespace sp_cypher;

    crypto::text input_text("bori");
    block b(input_text);

    block p_t = p_transform(b);
    block p_t_inv = p_transform_inv(p_t);

    std::cout << p_t << std::endl;
    std::cout << p_t_inv << std::endl;

}
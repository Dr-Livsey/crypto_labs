#include "algo.h"
#include "file.h"
#include <iostream>

int main( void )
{
    crypto::file file("text.txt");
    
    crypto::text plain_text(file);
    crypto::key k = { 'a', 'b', 'l' };

    crypto::alph al(file);

    std::cout << al;

    crypto::vigenere vig_al(al);

    crypto::text cypher = vig_al.encrypt(plain_text, k);

    crypto::file encr_file("encr_text.txt", std::ios::out);
    encr_file << cypher;

    crypto::text plain = vig_al.decrypt(cypher, k);

    crypto::file decr_file("decr_text.txt", std::ios::out);
    decr_file << plain;


    return EXIT_SUCCESS;
}
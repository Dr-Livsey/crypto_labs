#include "frontend.h"
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
int main(int argc, char *argv[]) 
{
    return frontend::run(argc, argv);
}

    // crypto::file input_file("text.txt");
    // crypto::text input_text = input_file;

    // sp_cypher::key k("bori");
    // sp_cypher::subst S("src/sub.json");

    // crypto::text cypher = sp_cypher::encrypt(k, input_text, S);
    // crypto::text decypher = sp_cypher::decrypt(k, cypher, S);

    // crypto::file encr_file("encr_text.txt", std::ios::out | std::ios::binary);
    // encr_file << cypher;
    // crypto::file decr_file("decr_text.txt", std::ios::out | std::ios::binary);
    // decr_file << decypher;
#include "algo.h"
#include "fdict.h"
#include <iostream>
#include <algorithm>

crypto::text
crypto::vigenere::encrypt( 
    const text &plain_text, const key &k)
{
    if (al.is_belongs(k) == false){
        throw std::runtime_error("Key is not belongs to alphabet!");
    }
    if (plain_text.empty()){
        throw std::runtime_error("Plain text is empty!");
    }
    if (k.empty()){
        throw std::runtime_error("Key is empty!");
    }
    if (al.empty()){
        throw std::runtime_error("Alph is empty!");
    }

    // Plain text size
    std::size_t pt_size = plain_text.size();

    // Expand key
    key  ext_k = k;
    ext_k.expand(pt_size);

    return al.vector_conv(plain_text, ext_k, alph::conv_t::direct);
}

crypto::text
crypto::vigenere::decrypt( 
    const text &cypher_text, const key &k)
{
    if (al.is_belongs(k) == false){
        throw std::runtime_error("Key is not belongs to alphabet!");
    }
    if (cypher_text.empty()){
        throw std::runtime_error("Cypher text is empty!");
    }
    if (k.empty()){
        throw std::runtime_error("Key is empty!");
    }
    if (al.empty()){
        throw std::runtime_error("Alph is empty!");
    }

    // Cypher text size
    std::size_t ct_size = cypher_text.size();

    // Expand key
    key  ext_k = k;
    ext_k.expand(ct_size);

    return al.vector_conv(ext_k, cypher_text, alph::conv_t::reverse);
}

crypto::text
crypto::autokey_v2::encrypt(
    const text &plain_text, const key &key)
{
    std::size_t key_size = key.size();
    crypto::key cur_key  = key;
    text        cypher;

    vigenere vigenere_cypher(this->al);

    for (auto pt_iter = plain_text.cbegin(); pt_iter != plain_text.cend(); /**/)
    {
        /* 
            Remaining unencrypted length of plain text.
        */
        std::size_t rem_len =  static_cast<std::size_t>(plain_text.cend() - pt_iter);
        /* 
           Size of chunk is the min of remaining length 
           and key size.
        */
        std::size_t size_of_chunk = std::min(rem_len, key_size);

        text pt_chunk(pt_iter, pt_iter + size_of_chunk);

        cur_key  = vigenere_cypher.encrypt(pt_chunk, cur_key);
        cypher  += cur_key;
        pt_iter += size_of_chunk;
    }

    return cypher;
}

crypto::text
crypto::autokey_v2::decrypt(
    const text &cypher_text, const key &key)
{
    std::size_t key_size = key.size();
    text        plain_text;

    if (key_size > cypher_text.size())
        throw  std::runtime_error("Key size must be <= Cypher text size");
    
    plain_text += al.vector_conv(key, cypher_text, alph::conv_t::reverse);

    for (auto c_iter = cypher_text.cbegin(); c_iter != (cypher_text.cend() - key_size); c_iter++){
        plain_text += { al.reverse_conv(*c_iter, *(c_iter + key_size)) };
    }

    return plain_text;
}

crypto::text
crypto::autokey_v2::decrypt(
    const text &cypher_text, const std::size_t &key_size)
{
    text        plain_text;

    if (key_size > cypher_text.size())
        throw  std::runtime_error("Key size must be <= Cypher text size");
    
    // Copy first key_size bytes
    plain_text.insert(plain_text.end(), cypher_text.begin(), cypher_text.begin() + key_size);

    for (auto c_iter = cypher_text.cbegin(); c_iter != (cypher_text.cend() - key_size); c_iter++){
            plain_text += { al.reverse_conv(*c_iter, *(c_iter + key_size)) };
    }

    return plain_text;
}

crypto::key
crypto::algorithms::frequency_method( const text &cypher, const std::size_t &key_size, const fdict &pt_freq )
{
    /* 
        Divide cypher text into slices equal to length of the key
        and push it to the vector 
    */
    text::slices cypher_slices = cypher.split(key_size);

    alph pt_alph = pt_freq.keys();

    // Obtain index of the most frequent byte in the plain text
    byte most_frequent = pt_freq.get_most_frequent().first;

    // Getting global index - index of the most frequent byte in !plain text!
    byte global_index = pt_alph.index(most_frequent);

    key result;

    for ( std::size_t column = 0; column < key_size; column++ )
    {
        text column_bytes;
        for ( size_t j = 0; j < cypher_slices.size() ; j++ )
        {    
            if (column < cypher_slices.at(j).size())
                column_bytes.push_back(cypher_slices.at(j).at(column));
        }

        // Getting local index - index of the most frequent byte in 'column'
        fdict column_freq(column_bytes);
    
        byte local_index = pt_alph.index(column_freq.get_most_frequent().first);

        std::size_t offset = (local_index - global_index + pt_alph.size()) % pt_alph.size();

        result.push_back(pt_alph.at(offset));
    }

    return result;
}

std::vector<crypto::key>
crypto::algorithms::friedman2_method( const text &cypher_text, const std::size_t &key_size, const crypto::fdict &pt_freqs )
{
    if (key_size < 2){
        throw std::runtime_error("Key size must be > 1");
    }

    text::slices cypher_slices = cypher_text.split(key_size);
    text::slices columns;

    // Each column corresponds to appropriate key byte
    for ( std::size_t column = 0; column < key_size; column++ )
    {
        text column_bytes;
        for ( size_t j = 0; j < cypher_slices.size() ; j++ )
        {    
            if (column < cypher_slices.at(j).size())
                column_bytes.push_back(cypher_slices.at(j).at(column));
        }
        columns.push_back(column_bytes);
    }

    std::map<byte, byte> shift_map = {{0, 0}};

    double global_delta = pt_freqs.get_delta();

    crypto::alph pt_alph      = pt_freqs.keys();
    std::size_t  pt_alph_size = pt_freqs.size();

    //Find the mutual match index for each column with first
    for ( std::size_t i = 1; i < columns.size(); i++)
    {
        std::vector<double> match_indexes;

        double min_delta    = global_delta;
        byte   global_shift = 0;

        // Find local_shift with min delta
        for ( byte local_shift = 0; local_shift < pt_alph_size; local_shift++)
        {
            double cur_match_idx = get_mut_match_index(columns[0], columns[i].right_shift(local_shift, pt_alph));

            double local_delta = std::fabs(global_delta - cur_match_idx);
            
            if (local_delta < min_delta){
                global_shift = local_shift;
                min_delta    = local_delta;
            }
        }

        shift_map[i] = global_shift;
    }

    // Calculate keys with obtained offsets in shift map
    auto get_key = [&pt_alph, &shift_map](const crypto::byte &alph_item) -> crypto::key
    {
        crypto::key cur_key;

        // Shift all key bytes by offsets in shift_map relative to first byte
        for ( std::size_t i = 0; i < shift_map.size(); i++){
            cur_key += { pt_alph.left_shift(alph_item, shift_map.at(i))};
        }

        return cur_key;
    };

    std::vector<key> keys(pt_alph.size());

    // Get first byte with frequency method
    crypto::byte local_index  = pt_alph.index(crypto::fdict::get_freq(columns.at(0)).get_most_frequent().first);
    crypto::byte global_index = pt_alph.index(pt_freqs.get_most_frequent().first); 
    std::size_t  offset       = (local_index - global_index + pt_alph.size()) % pt_alph.size();

    std::cout << "Most probability key is: [" << get_key(pt_alph.at(offset)) << "]" << std::endl;

    for ( auto alph_item : pt_alph ){
        keys.push_back(get_key(alph_item));
    }

    return keys;
}

double 
crypto::algorithms::get_mut_match_index( const text &ltext, const text &rtext )
{
    fdict   max_freq = fdict::get_freq(ltext);
    fdict   min_freq = fdict::get_freq(rtext);

    if (max_freq.size() < min_freq.size()){
        max_freq.swap(min_freq);
    }

    alph    min_alph = min_freq.keys(); 

    double retval    = 0.;

    for ( auto it = min_alph.cbegin(); it != min_alph.cend(); it++ )
    {
        if ( max_freq.find(*it) != max_freq.end() )
        {
            double mint_fvalue = min_freq.at(*it);
            double maxt_fvalue = max_freq.at(*it);

            retval += mint_fvalue * maxt_fvalue;
        }
    }

    return retval;
}

std::size_t
crypto::algorithms::kasiski_method(const text &txt, const std::size_t &n)
{
    std::unordered_map<std::size_t, std::size_t> all_gcd;

    if (n == 0){
        throw std::runtime_error("ngrams length must be > 0");
    }

    for ( auto cur_ngram : txt.as_ngrams(n) )
    {
        // Find all distances
        text::distances dist_vec = txt.find_all(cur_ngram);
        // Min. three occurances
        if ( dist_vec.size() < 2){
            continue;
        }
        // Find GCD between all occurences of current ngram
        std::size_t result = dist_vec[1] - dist_vec[0];

        for (std::size_t i = 1; i < dist_vec.size(); i++){
            result = std::gcd(result, dist_vec[i] - dist_vec[0]);
        }

        all_gcd[result] += 1;
    }

    // Find most frequent GCD
    std::size_t max_frequency = 0, result_gcd = 0;
    for (auto pair : all_gcd) 
    {
        if (pair.second > max_frequency) {
            max_frequency = pair.second;
            result_gcd    = pair.first;
        }
    }
     
    return result_gcd;
}

bool
crypto::key::expand( std::size_t new_size )
{
    if (this->empty())
        throw std::runtime_error("Key is empty!");

    std::size_t start_size = this->size();

    bool status = (new_size >= start_size) ? true : false;

    if (status == false){
        return false;
    }
    else if (new_size == start_size) {
        return true; 
    }

    key acc = *this;
    std::size_t excess = ((new_size / start_size) + 1) * start_size - new_size;

    for (std::size_t  i = 0; i < (new_size / start_size); i++){
        insert(end(), acc.begin(), acc.end());
    }

    this->resize(this->size() - excess);

    return true;
}

void
crypto::cypher::set_alph( const alph &new_al)
{
    this->al = new_al;
}

crypto::alph
crypto::cypher::get_alph( void ) const
{
    return this->al;
}

std::ostream& 
operator<<( std::ostream& stream, const std::vector<crypto::key>& obj)
{
    for (auto i = obj.begin(); i != obj.end(); i++) 
    {
        stream << *i << std::endl;
    }
    return stream;
}
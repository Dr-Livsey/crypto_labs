#include "text.h"
#include "file.h"
#include "nlohmann/json.hpp"
#include <iomanip>
#include <algorithm>

crypto::text::text( file &fd )
{
    from_file(fd);
}

crypto::text::text(
    const std::initializer_list<byte> &init_list) 
    : std::vector<byte>(init_list) {}

crypto::text::text(
    const std::string &init_s) {
    
    insert(begin(), init_s.begin(), init_s.end());
}

crypto::text::text( 
    const text::const_iterator &start, const text::const_iterator &fin ) 
    : std::vector<byte>(start, fin) {}

void
crypto::text::from_file(file &fd)
{
    //Save current state and pos
    std::ios::iostate state_flags = fd.rdstate();
    fd.clear();
    std::streampos cur_pos = fd.tellg();
    //Get size
    std::streampos file_size = fd.size();

    reserve(file_size);

    fd.rewind(0);

    while (fd.is_eof_reached() == false) 
    {
        push_back(fd.read_byte());
    }

    //Returning to the start state
    fd.rewind(cur_pos);
    fd.setstate(state_flags);   
}

crypto::text
crypto::text::first_bytes( const std::size_t &len ) const
{
    return text(this->cbegin(), this->cbegin() + std::min(len, this->size()));
}

std::string 
byte_to_hex( const crypto::byte &b )
{
    std::stringstream ss;

    ss << std::hex << std::setfill('0') << std::setw(2) << +b;

    return "0x" + ss.str();
}

crypto::text::slices
crypto::text::split( const std::size_t &size ) const
{
    slices retval;

    for ( std::size_t i = 0; i < this->size(); i += size )
    {
        auto cur_pos = this->begin() + i;

        text slice(cur_pos, cur_pos + std::min(size, this->size() - i));

        retval.push_back(slice);
    }

    return retval;
}

crypto::text&
crypto::text::operator+=( const crypto::text &rhs )
{
    this->insert(end(), rhs.begin(), rhs.end());
    return *this;
}

crypto::text
crypto::text::operator+( const crypto::text &rhs )
{
    text result(*this);
    result.insert(result.end(), rhs.begin(), rhs.end());
    return result;
}

// Operations with output stream
std::ostream& 
operator<<( std::ostream& stream, const crypto::text& obj)
{
    for (auto i = obj.begin(); i != obj.end(); i++) 
    {
        stream << *i;
    }
    return stream;
}
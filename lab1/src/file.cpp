
#include "file.h"
#include <iostream>

crypto::file::file( const std::string &path, std::ios::openmode _openmode ) 
                : std::fstream(path, _openmode), opmode(_openmode)
{
    if (is_open() == false)
        throw std::ios::failure("File \"" + std::string(path) + "\" was failed to open!");

    this->unsetf(std::ios::skipws);
    this->exceptions(std::ios::badbit | std::ios::failbit);
}

bool
crypto::file::is_eof_reached( void )
{
    peek();
    return eof();
}

crypto::byte
crypto::file::read_byte()
{
    byte b;
    read((char*)&b, sizeof(byte));
    return b;
}

std::streampos
crypto::file::size()
{
    std::ios::iostate state_flags = rdstate();
    clear();
    std::streampos cur = tellg();

    rewind(0, std::ios::end);
    std::streampos fileSize = tellg();

    rewind(cur);
    setstate(state_flags);

    return fileSize;
}

void 
crypto::file::rewind( std::streampos pos, std::ios::seekdir seekdir )
{
    clear();
    seek(pos, seekdir);
}

void 
crypto::file::seek( std::streampos pos, std::ios::seekdir seekdir )
{
    if (opmode & std::ios::in) seekg(pos, seekdir);
    else
        seekp(pos, seekdir);
}

crypto::file::~file()
{
    if (this->is_open()) this->close();
}
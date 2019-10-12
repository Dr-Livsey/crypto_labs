#include <fstream>

namespace crypto
{
    using byte = unsigned char;

    class file : public std::fstream
    {
    public:

        file( 
            const std::string &, 
            std::ios::openmode _openmode = (std::ios::in | std::ios::binary) 
        );
        ~file();

        bool is_eof_reached();

        byte read_byte();

        std::streampos size();

        // Clear state flags 
        void rewind( std::streampos, std::ios::seekdir seekdir = std::ios::beg );
        // Without clear state flags
        void seek( std::streampos, std::ios::seekdir seekdir = std::ios::beg );

    private:
        std::ios::openmode opmode;
        file(){}
    };

};
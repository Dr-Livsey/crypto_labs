#include <iostream>
#include <bitset>

unsigned cycle_shift(unsigned long b, int n)
{
    unsigned LBIT = 0x80000000;
    unsigned RBIT = 0x00000001;
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

    return static_cast<unsigned>(b);
}


int main(int argc, char *argv[]) {
	

	unsigned shifted = cycle_shift(std::stoul(argv[1], nullptr, 10), std::atoi(argv[2]));

	std::cout << "Dec: " << shifted << std::endl;
	std::cout << "Hex: 0x" << std::hex << shifted << std::endl;
	std::cout << "Bin: 0b" << std::bitset<32>(shifted) << std::endl;
	return 0;
}

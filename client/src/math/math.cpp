#include "math.hpp"

#include <algorithm>

const std::map<char, int> Math::hex_map =
{
    std::make_pair('0', 0),
    std::make_pair('1', 1),
    std::make_pair('2', 2),
    std::make_pair('3', 3),
    std::make_pair('4', 4),
    std::make_pair('5', 5),
    std::make_pair('6', 6),
    std::make_pair('7', 7),
    std::make_pair('8', 8),
    std::make_pair('9', 9),
    std::make_pair('a', 10),
    std::make_pair('b', 11),
    std::make_pair('c', 12),
    std::make_pair('d', 13),
    std::make_pair('e', 14),
    std::make_pair('f', 15)
};

void Math::fromHexToChar(char* msg, const char* hex_str, size_t size)
{
    size_t s = size / 2;
    
    for(size_t i = 0; i < s; ++i)
    {
        msg[i] = hex_map.at(hex_str[i * 2 + 1]) * 16 + hex_map.at(hex_str[i * 2]);
    }
}

void Math::fromCharToHex(char* hex_str, const char * str, size_t size)
{
    for(size_t i = 0; i < size; ++i)
    {
        uint8_t a = (uint8_t)(str[i]) >> 4;
        uint8_t b = (uint8_t)(str[i]) % 16;

        if(a > 15 || b > 15)
        {
            exit(1);
        }

        hex_str[i * 2 + 1] = hex_array[a];
        hex_str[i * 2] = hex_array[b];
    }
}

void Math::findOnlyHex(const char* msg, int size, std::string& output)
{
    for(int i = 0; i < size; ++i)
    {
        for(int j = 0; j < 16; ++j)
        {
            if(hex_array[j] == msg[i])
            {
                output += msg[i];
            }
        }
    }
}
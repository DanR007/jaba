#pragma once
#include <map>
#include <inttypes.h>
#include <iostream>
#include <string>

class Math
{
public:
    static void fromHexToChar(char* msg, const char* str, size_t size);
    static void fromCharToHex(char* msg, const char* hex_str, size_t size);

    static void findOnlyHex(const char* msg, int size, std::string& output);
private:
    static constexpr char* hex_array = "0123456789abcdef";
    static const std::map<char, int> hex_map;
};




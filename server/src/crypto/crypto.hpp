#pragma once

#include "gost_defined.hpp"

#include <string>

class Crypto
{
public:
    static void Configure();
    static void GenerateKeys(int bits = 4096);
    static char* Encrypt( const char* data, int size, const std::string& key_name );
    static char* Decrypt(const char* msg);
    static char* GetPublKey();

    static int getSizeBlockMessage() { return c_size_block_msg; }
    static int getSizeBlockEncryptHex() { return c_size_block_encrypt * 2; }

    static void X(const uint8_t* a, const uint8_t* b, uint8_t *c);

    static void gost_Encrypt( const uint8_t* message, uint8_t* encrypted_message, const uint8_t** iter_keys);
    static void gost_Decrypt( const uint8_t* encrypted_message, uint8_t* decrypted_message, const uint8_t** iter_keys );

    static void ExpandKey(const uint8_t *key, uint8_t* iter_key[16]);
    static void GetC();
private:
    
    static uint8_t iter_C[32][BLOCK_SIZE];

    //Определение всех функций
    static uint8_t multiply(const uint8_t a, const uint8_t b);
    
    static void R(uint8_t* state);
    static void R_Reverse(uint8_t *state);
    static void L(const uint8_t *in_data, uint8_t *out_data);
    static void L_Reverse(const uint8_t *in_data, uint8_t *out_data);
    
    
    static void F(const uint8_t *in_key_1, const uint8_t *in_key_2,
                            uint8_t *out_key_1, uint8_t *out_key_2,
                            uint8_t *iter_const);
    static void S(const uint8_t *in_data, uint8_t *out_data);
    static void S_Reverse(const uint8_t *in_data, uint8_t *out_data);

    static constexpr int c_size_block_encrypt = 512;
    static constexpr int c_size_block_msg = 400;

    static constexpr char* _public_key_file_name = "public_key";
    static constexpr char* _private_key_file_name = "private_key.pem";
};
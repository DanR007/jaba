#include "crypto.hpp"

#include <iostream>
#include <filesystem>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "../math/math.hpp"
#include "../colour.hpp"

uint8_t Crypto::iter_C[32][BLOCK_SIZE];

void Crypto::Configure()
{
    OpenSSL_add_all_algorithms();
}

void Crypto::GenerateKeys(int bits)
{
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    unsigned long e_value = 65537;
    BN_set_word(e, e_value);

    RSA_generate_key_ex(rsa, bits, e, nullptr);

    BIO* bio_private = BIO_new_file(_private_key_file_name, "w");
    PEM_write_bio_RSAPrivateKey(bio_private, rsa, nullptr, nullptr, 0, nullptr, nullptr);

    BIO* bio_public = BIO_new_file(_public_key_file_name, "w");
    PEM_write_bio_RSAPublicKey(bio_public, rsa);

    BIO_free(bio_private);
    BIO_free(bio_public);
    RSA_free(rsa);
    BN_free(e); 
}

//return public key in pem format
char* Crypto::GetPublKey()
{
    RSA *public_key = RSA_new();

    FILE* f_public = fopen(_public_key_file_name, "rb");
    if(!f_public)
    {
        GenerateKeys();
        f_public = fopen(_public_key_file_name, "rb");
    }

    public_key = PEM_read_RSAPublicKey(f_public, nullptr, nullptr, nullptr);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, public_key);

    char* key_data;
    BIO_get_mem_data(bio, &key_data);

    RSA_free(public_key);
    fclose(f_public);
    BIO_free(bio);

    return key_data;
}

char* Crypto::Encrypt( const char* data, int size, const std::string& key_name )
{
    if( std::filesystem::exists( "keys/"+key_name ) == false )
    {
        std::cout << RED_BOLD "Нет ключа" NONE_FORMAT "\n";
        return nullptr;
    }

    FILE* f_public = fopen( ("keys/"+key_name).c_str(), "rb" );
    RSA* public_key = PEM_read_RSAPublicKey(f_public, nullptr, nullptr, nullptr);

    uint8_t *msg_char = new uint8_t[size];
            
    memcpy(msg_char, data, size);

    uint8_t *enc_msg = new uint8_t[c_size_block_encrypt];
    
    if(RSA_public_encrypt(size, (msg_char), enc_msg, public_key, RSA_PKCS1_PADDING) == -1)
    {
        std::cout << "mdaaaaaa encrypt govna\n";
        exit(1);
    }

    char* hex_encrypt = new char[c_size_block_encrypt * 2];
    Math::fromCharToHex(hex_encrypt, (char*)enc_msg, c_size_block_encrypt);
    //std::cout << hex_encrypt << std::endl;
    delete[] msg_char;
    RSA_free(public_key);
    fclose(f_public);
        
    return hex_encrypt;
}

char* Crypto::Decrypt(const char* msg)
{
    RSA *private_key = RSA_new();
    FILE* f_private = fopen(_private_key_file_name, "rb");
    private_key = PEM_read_RSAPrivateKey(f_private, nullptr, nullptr, nullptr);
    
    char* message = new char[c_size_block_encrypt];

    std::string output = "";
    Math::findOnlyHex(msg, strlen(msg), output);

    Math::fromHexToChar( message, output.c_str(), output.size() );

    uint8_t* decrypt_msg = new uint8_t[c_size_block_msg];

    if(RSA_private_decrypt(c_size_block_encrypt, (const uint8_t*)(message), decrypt_msg, private_key, RSA_PKCS1_PADDING) == -1)
    {
        char err_msg[120];
        std::cerr << "OpenSSL Error: " << err_msg << std::endl;
        std::cout << "mdaaaaaa decrypt govna\n";
    }

    delete[] message;
    RSA_free(private_key);
    fclose(f_private);

    return (char*)decrypt_msg;
}

void Crypto::gost_Encrypt(const uint8_t* message, uint8_t* encrypted_message, const uint8_t** iter_keys)
{
    memcpy(encrypted_message, message, BLOCK_SIZE);

    for(int i = 0; i < 9; ++i)
    {
        X(iter_keys[i], encrypted_message, encrypted_message);
        S(encrypted_message, encrypted_message);
        L(encrypted_message, encrypted_message);
    }

    X(iter_keys[9], encrypted_message, encrypted_message);   
}

void Crypto::gost_Decrypt(const uint8_t* encrypted_message, uint8_t* decrypted_message, const uint8_t** iter_keys)
{
    memcpy(decrypted_message, encrypted_message, BLOCK_SIZE);

    X(iter_keys[9], encrypted_message, decrypted_message);
    for(int i = 8; i >= 0; --i)
    {
        L_Reverse(decrypted_message, decrypted_message);
        S_Reverse(decrypted_message, decrypted_message);
        X(decrypted_message, iter_keys[i], decrypted_message);
    }
}

void Crypto::S(const uint8_t *in_data, uint8_t *out_data)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        out_data[i] = Pi[in_data[i]];
    }
}

void Crypto::S_Reverse(const uint8_t *in_data, uint8_t *out_data)
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
    {
        out_data[i] = reverse_Pi[in_data[i]];
    }
}

void Crypto::X(const uint8_t* a, const uint8_t* b, uint8_t *c)
{
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void Crypto::R(uint8_t* state)
{
    int i;
    uint8_t a_15 = 0;
    vect internal;
    for (i = 15; i >= 0; i--)
    {
        if (i - 1 >= 0)
        {
            internal[i - 1] = state[i];
        }
        a_15 ^= multiply(state[i], l_vec[i]);
    }
    internal[15] = a_15;
    memcpy(state, internal, BLOCK_SIZE);
}

void Crypto::R_Reverse(uint8_t *state)
{
    int i;
    uint8_t a_0;
    a_0 = state[15];
    vect internal;
    for (i = 1; i < 16; i++)
    {
        internal[i] = state[i - 1];
        a_0 ^= multiply(internal[i], l_vec[i]);
    }
    internal[0] = a_0;
    memcpy(state, internal, BLOCK_SIZE);
}

uint8_t Crypto::multiply(uint8_t a, uint8_t b)
{
    uint8_t c = 0;
    uint8_t hi_bit;
    int i;
    for (i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            c ^= a;
        }
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit)
        {
            a ^= 0xc3; //полином x^8+x^7+x^6+x+1
        }
        b >>= 1;
    }
    return c;
}

void Crypto::L(const uint8_t *in_data, uint8_t *out_data)
{
    int i;
    vect internal;
    memcpy(internal, in_data, BLOCK_SIZE);
    for (i = 0; i < 16; i++)
    {
        R(internal);
    }
    memcpy(out_data, internal, BLOCK_SIZE);
}

void Crypto::L_Reverse(const uint8_t *in_data, uint8_t *out_data)
{
    int i;
    vect internal;
    memcpy(internal, in_data, BLOCK_SIZE);
    for (i = 0; i < 16; i++)
    {
        R_Reverse(internal);
    }
    memcpy(out_data, internal, BLOCK_SIZE);
}

void Crypto::GetC()
{
    int i;
    vect iter_num[32];
    for (i = 0; i < 32; i++)
    {
        memset(iter_num[i], 0, BLOCK_SIZE);
        iter_num[i][0] = i+1;
    }
    for (i = 0; i < 32; i++)
    {
        L(iter_num[i], iter_C[i]);
    }
}

void Crypto::F(const uint8_t *in_key_1, const uint8_t *in_key_2,
                            uint8_t *out_key_1, uint8_t *out_key_2,
                            uint8_t *iter_const)
{
    vect internal;
    memcpy(out_key_2, in_key_1, BLOCK_SIZE * sizeof(uint8_t));
    X(in_key_1, iter_const, internal);
    S(internal, internal);
    L(internal, internal);
    X(internal, in_key_2, out_key_1);
}

void Crypto::ExpandKey(const uint8_t *key, uint8_t* iter_key[BLOCK_SIZE])
{
    int i;
    uint8_t key_1[BLOCK_SIZE];
    uint8_t key_2[BLOCK_SIZE];
    uint8_t iter_1[BLOCK_SIZE];
    uint8_t iter_2[BLOCK_SIZE];
    uint8_t iter_3[BLOCK_SIZE];
    uint8_t iter_4[BLOCK_SIZE];
    memcpy(key_1, key + BLOCK_SIZE, BLOCK_SIZE);
    memcpy(key_2, key, BLOCK_SIZE);
    memcpy(iter_key[0], key_1, BLOCK_SIZE);
    memcpy(iter_key[1], key_2, BLOCK_SIZE);

    memcpy(iter_1, key_1, BLOCK_SIZE);
    memcpy(iter_2, key_2, BLOCK_SIZE);
    for (i = 0; i < 4; i++)
    {
        F(iter_1, iter_2, iter_3, iter_4, iter_C[0 + 8 * i]);
        F(iter_3, iter_4, iter_1, iter_2, iter_C[1 + 8 * i]);
        F(iter_1, iter_2, iter_3, iter_4, iter_C[2 + 8 * i]);
        F(iter_3, iter_4, iter_1, iter_2, iter_C[3 + 8 * i]);
        F(iter_1, iter_2, iter_3, iter_4, iter_C[4 + 8 * i]);
        F(iter_3, iter_4, iter_1, iter_2, iter_C[5 + 8 * i]);
        F(iter_1, iter_2, iter_3, iter_4, iter_C[6 + 8 * i]);
        F(iter_3, iter_4, iter_1, iter_2, iter_C[7 + 8 * i]);
        memcpy(iter_key[2 * i + 2], iter_1, BLOCK_SIZE);
        memcpy(iter_key[2 * i + 3], iter_2, BLOCK_SIZE);
    }

    
}


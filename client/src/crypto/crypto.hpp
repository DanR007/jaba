#pragma once

#include "gost_defined.hpp"

class Crypto
{
public:
    /// @brief подгружаем шифры
    static void Configure();
    /// @brief генерация пары RSA ключей
    /// @param bits во сколько битов ключ
    static void GenerateKeys(int bits = 4096);
    /// @brief шифрование открытым ключом сервера
    /// @param data 
    /// @param size 
    /// @return 
    static char* Encrypt(const char* data, int size);
    /// @brief расшифровка нашим закрытым ключом
    /// @param msg входящий зашифрованный трафик
    /// @return 
    static char* Decrypt(const char* msg);
    /// @brief считывание публичного ключа
    /// @return 
    static char* GetPublKey();

    static int getSizeBlockMessage() { return c_size_block_msg; }
    static int getSizeBlockEncryptHex() { return c_size_block_encrypt * 2; }

    /// @brief XOR операция 
    /// @param a первый операнд
    /// @param b второй операнд
    /// @param c результат
    static void X(const uint8_t* a, const uint8_t* b, uint8_t *c);
    /// @brief шифрование кузнечиком
    /// @param message входное сообщение
    /// @param encrypted_message выход зашифрованного сообщения
    static void gost_Encrypt(const uint8_t* message, uint8_t* encrypted_message);
    /// @brief расшифровка кузнечиком
    /// @param message входное сообщение
    /// @param encrypted_message выход расшифрованного сообщения
    static void gost_Decrypt(const uint8_t* encrypted_message, uint8_t* decrypted_message);
    /// @brief создание 10 раундовых ключей
    /// @param key входной ключ 256 бит
    static void ExpandKey(const uint8_t *key);
private:
    
    static uint8_t iter_C[32][BLOCK_SIZE];
    static uint8_t iter_key[10][BLOCK_SIZE];

    /// @brief умножение в 256 кольце
    /// @param a 
    /// @param b 
    /// @return результат перемножения
    static uint8_t multiply(const uint8_t a, const uint8_t b);
    /// @brief линейное преобразование часть с перемножением и сдвигом 
    /// @param state 
    static void R(uint8_t* state);
    /// @brief обратное линейное преобразование часть с перемножением и сдвигом 
    /// @param state 
    static void R_Reverse(uint8_t *state);
    /// @brief линейное преобразование
    /// @param in_data 
    /// @param out_data 
    static void L(const uint8_t *in_data, uint8_t *out_data);
    /// @brief обратное линейное преобразование со сдвигом
    /// @param in_data 
    /// @param out_data 
    static void L_Reverse(const uint8_t *in_data, uint8_t *out_data);
    /// @brief создание раундовых констант для ключей
    static void GetC();
    
    /// @brief сеть Фейстеля
    /// @param in_key_1 
    /// @param in_key_2 
    /// @param out_key_1 
    /// @param out_key_2 
    /// @param iter_const 
    static void F(const uint8_t *in_key_1, const uint8_t *in_key_2,
                            uint8_t *out_key_1, uint8_t *out_key_2,
                            uint8_t *iter_const);
    /// @brief нелинейное преобразование с перестановками
    /// @param in_data 
    /// @param out_data 
    static void S(const uint8_t *in_data, uint8_t *out_data);
    /// @brief обратное нелинейное преобразование с перестановками
    /// @param in_data 
    /// @param out_data 
    static void S_Reverse(const uint8_t *in_data, uint8_t *out_data);

    static constexpr int c_size_block_encrypt = 512;
    static constexpr int c_size_block_msg = 400;

    static constexpr char* _public_key_file_name = "public_key";
    static constexpr char* _private_key_file_name = "private_key.pem";
};
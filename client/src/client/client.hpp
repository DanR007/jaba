#pragma once

#define BLOCK_SIZE 16
#define KEY_SIZE 32

#include <string>
#include <memory>

#include <boost/asio.hpp>

class XMLParser;

struct Message
{
    std::string _sender;
    std::string _data;
};

struct Connection
{
    int _sock = 0;

    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf read_buffer;

    Connection( boost::asio::io_service & io_service ) : socket( io_service ), read_buffer( )
    {

    }
    Connection( boost::asio::io_service & io_service, size_t max_buffer_size ) : socket( io_service ), read_buffer( )
    {

    }
};

class Client
{
public:
    Client( ) = delete;
    Client( const std::string& jid );
    ~Client( );

    /// @brief запуск работы потока ввода вывода
    void run( );

    /// @brief инициация подключения к серверу
    void connectToServer( );
    void disconnectFromServer( );
    /// @brief результат отправки на сервер
    /// @param err статус ошибки
    void handleWrite( boost::system::error_code const & err );
    /// @brief обработка пришедшего сообщения
    /// @param err статус ошибки
    /// @param bytes_transfered сколько байт считали
    void handleRead( boost::system::error_code const & err, size_t bytes_transfered );
    /// @brief результат подключения
    /// @param ec результат ошибки
    void handleConnect( const boost::system::error_code& ec );
    
    /// @brief запуск асинхронного подключения к серверу
    void asyncRead( );
    /// @brief асинхронный набор сообщения для отправки на сервер
    void asyncWrite( );

    void grabInput( );
    /// @brief выбор того, с кем ведем диалог
    void choiceRecipient( );
    /// @brief инициация регистрации
    void signIn( );
    /// @brief запуск слушания сообщений от сервера и отправки сообщений
    void work( );
private:
    void requestSignIn( boost::system::error_code const &err, size_t bytes_transfered );
    
    void parse( size_t bytes_transfered );

    void receiveSignInResult( boost::system::error_code const & err );

    void printChoiceRecipientPage( );

    void printUI( );

    std::shared_ptr<XMLParser> _parser;

    std::string _recipient;
    std::string _jid;
    std::string _address;

    boost::asio::io_service _ioservice;
    boost::asio::ip::tcp::socket _sock;

    boost::asio::streambuf _read_buffer;
    /// @brief RSA шифрование
    /// @param data 
    /// @param size 
    /// @return 
    char* Encrypt( const char* data, size_t size );
    /// @brief RSA дешифрование
    /// @param data 
    /// @param size 
    /// @return 
    char* Decrypt( const char* data );
    /// @brief кузнечик по сессионному ключу и вектору инициализации
    /// @param data сообщение
    /// @param size размер сообщения
    /// @param enc_str зашифрованное сообщение
    void gostEncrypt( const char* data, size_t size, std::string& enc_str );
    /// @brief кузнечик по сессионному ключу и вектору инициализации
    /// @param data зашифрованное сообщение
    /// @param dec_str расшифрованное сообщение
    void gostDecrypt( const char* data, std::string& dec_str);

    std::vector<Message> _message_buffer;
    
    bool bAuthorized = false;

    uint8_t iv[BLOCK_SIZE];
    uint8_t session_key[KEY_SIZE];
};
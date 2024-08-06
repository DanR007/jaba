#pragma once

#include <vector>
#include <string>
#include <list>
#include <memory>

#include <boost/asio.hpp>

class XMLParser;

struct Connection
{
    int _sock = 0;
    std::string _token;
    std::string _jid = "";
    std::string _key_name = "";
    
    std::shared_ptr<XMLParser> _parser;

    uint8_t** iter_key;

    boost::asio::ip::tcp::socket socket;
    boost::asio::streambuf read_buffer;

    std::string _last_message = "";

    Connection( boost::asio::io_service & io_service );
    Connection( boost::asio::io_service & io_service, size_t max_buffer_size );

    ~Connection();

    bool operator==(const std::string& jid)
    {
        return _jid == jid;
    }
};

class Server
{
private:
    boost::asio::io_service _ioservice;
    boost::asio::ip::tcp::acceptor _acceptor;
	using con_handle_t = std::list<Connection>::iterator;
    std::list<Connection> _connections;
    
    char* Encrypt( const char* data, size_t size, const std::string& jid );
    char* Decrypt( const char* data );
    
    void gostEncrypt( con_handle_t con_handle, const char* data, size_t size, std::string& enc_str );
    void gostDecrypt( con_handle_t con_handle, const char* data, std::string& dec_str);

    con_handle_t findConnection( const std::string& jid );

    void readInformation( con_handle_t con_handle );

    void parse( con_handle_t con_handle, size_t bytes_transfered );

    int variatyCommandToServer( const std::string& command );

    void authentication( con_handle_t con_handle );
    void waitToken( con_handle_t con_handle, boost::system::error_code const & err );
    void compareToken( con_handle_t con_handle, boost::system::error_code const & err, size_t bytes_transfered );

    void sendAuthenticationResult( con_handle_t con_handle, std::shared_ptr<std::string> msg );
public:
    Server(): _ioservice( ), _acceptor( _ioservice ), _connections( )
    {
        
    }
    ~Server();

    void startListen( uint16_t port );

    void handleWrite( con_handle_t con_handle, boost::system::error_code const & err );
    void handleRead( con_handle_t con_handle, boost::system::error_code const & err, size_t bytes_transfered );
    void handleConnect( con_handle_t con_handle, boost::system::error_code const & err );

    void run( );

    void asyncRead( con_handle_t con_handle );
    void asyncWrite( con_handle_t con_handle, std::shared_ptr<std::string> msg, const std::string& recipient );

    void startAccept( );
	
};



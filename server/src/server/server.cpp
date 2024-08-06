#include "server.hpp"
#include "../main.hpp"
#include "../colour.hpp"

#include <cstring>

#include "../parser/xml.hpp"
#include "../crypto/crypto.hpp"
#include "../math/math.hpp"

#include <boost/bind.hpp>

#include <strstream>
#include <sys/random.h>

Connection::Connection( boost::asio::io_service & io_service ) : socket( io_service ), read_buffer( )
{
    _parser = std::make_shared<XMLParser>();

	iter_key = new uint8_t*[10];

	for( int i = 0; i < 10; ++i )
	{
		iter_key[i] = new uint8_t[BLOCK_SIZE];
	}
}
Connection::Connection( boost::asio::io_service & io_service, size_t max_buffer_size ) : socket( io_service ), read_buffer( max_buffer_size )
{ 
    _parser = std::make_shared<XMLParser>();
}

Connection::~Connection()
{
	for( int i = 0; i < 10; ++i )
	{
		delete[] iter_key[i];
	}

	delete[] iter_key;
}

char *Server::Encrypt( const char *data, size_t size, const std::string& jid )
{
    return Crypto::Encrypt(data, size, jid);
}

char *Server::Decrypt(const char *data)
{
    return Crypto::Decrypt(data);
}

void Server::gostEncrypt( con_handle_t con_handle, const char *data, size_t size, std::string &enc_str)
{
	uint8_t* iv = new uint8_t[BLOCK_SIZE];

	memcpy(iv, (con_handle->_token.c_str() + KEY_SIZE), BLOCK_SIZE);

	size_t full_size = size;
    if( size % 16 )
    {
        full_size += (16 - size % 16);
    }
    char* tmp_data = new char[ full_size ];

    strncpy( tmp_data, data, size );
    memset( tmp_data + size, 0, full_size - size );

    for( size_t i = 0; i < full_size; i += BLOCK_SIZE )
    {
        uint8_t* message = new uint8_t[BLOCK_SIZE];
        uint8_t* encrypt_message = new uint8_t[BLOCK_SIZE];

        memset( message, 0, BLOCK_SIZE );
        memcpy( message, tmp_data + i, std::min( ( size_t ) BLOCK_SIZE, strlen( tmp_data + i ) ) );

        Crypto::gost_Encrypt(message, encrypt_message, (const uint8_t**)con_handle->iter_key);

        Crypto::X(encrypt_message, iv, encrypt_message);

        uint8_t enc_hex[BLOCK_SIZE * 2];
        Math::fromCharToHex((char*)enc_hex, (const char*)encrypt_message, BLOCK_SIZE);

        for( int j = 0; j < KEY_SIZE; ++j )
        {
            enc_str += (char)enc_hex[j];
        }

        delete[] message;
        delete[] encrypt_message;
    }

    delete[] tmp_data;
	delete[] iv;
}

void Server::gostDecrypt( con_handle_t con_handle, const char *data, std::string &dec_str )
{
	size_t size_input = strlen( data );
	if( size_input % 2 != 0 )
	{
		return;
	}

	std::string hex_str = "";
	Math::findOnlyHex( data, size_input, hex_str );

	if( hex_str.size() != size_input)
	{
		return;
	}


	uint8_t* iv = new uint8_t[BLOCK_SIZE];

	memcpy(iv, (con_handle->_token.c_str() + KEY_SIZE), BLOCK_SIZE);

	size_t size = strlen(data) / 2;
    char* tmp_data = new char[ strlen(data) / 2 ];
    Math::fromHexToChar(tmp_data, data, strlen(data));

    for( size_t i = 0; i < size; i += BLOCK_SIZE )
    {
        uint8_t* message = new uint8_t[BLOCK_SIZE];
        uint8_t* decrypt_message = new uint8_t[BLOCK_SIZE];

        memcpy( message, tmp_data + i, BLOCK_SIZE );

        Crypto::X( message, iv, message );

        Crypto::gost_Decrypt( message, decrypt_message, (const uint8_t**) con_handle->iter_key );

        dec_str.append((char*)decrypt_message);

        delete[] message;
        delete[] decrypt_message;
    }

    delete[] tmp_data;
	delete[] iv;
}

Server::con_handle_t Server::findConnection(const std::string &jid)
{
	auto it = std::find(_connections.begin(), _connections.end(), jid);
	if(it == _connections.end())
	{
		std::cerr << "Подключения " + jid + " не существует\n";
	}

    return it;
}

void Server::parse( con_handle_t con_handle, size_t bytes_transfered )
{
	char* msg = new char[bytes_transfered];
    std::istream is( &con_handle->read_buffer );

    is.read( msg, bytes_transfered );

	std::string str = "";

    str.append( msg );

    delete[] msg;

	size_t begin = str.find( "<message>" );
    size_t end = str.find( "</message>" ) + strlen( "</message>" );

	if( begin != std::string::npos && end != std::string::npos )
	{
    	str = str.substr( 
					str.find( "<message>" )
					, str.find( "</message>" ) + strlen( "</message>" ) );

		std::cout << "Message Received: \n" RED + str + NONE_FORMAT << std::endl;

		con_handle->_parser->parseXMLStr(str);
	}
	else
	{
		std::cout << "Нет начало или конца\n";
	}
	
}

int Server::variatyCommandToServer( const std::string& command )
{
	std::vector<std::string> commands = 
	{
		"wantToDisconnect",
		"signInRequest"
	};

	for( int i = 0; i < commands.size(); ++i)
	{
		if( command.find( commands[i] ) != std::string::npos )
		{
			return i;
		}
	}

    return -1;
}

void Server::authentication( con_handle_t con_handle )
{
	const int size = 48;
	char* buffer = new char[size];
	std::string buf;
	getrandom(buffer, size, 0);

	std::cout << RED << buffer << "\n" << NONE_FORMAT << std::endl;
	con_handle->_token.append( buffer );

	uint8_t key[KEY_SIZE] = { 0 };

	memcpy(key, con_handle->_token.c_str(), KEY_SIZE);

	Crypto::ExpandKey(key, con_handle->iter_key);

	buf = con_handle->_parser->configureString( con_handle->_jid, "", Encrypt( con_handle->_token.c_str(), con_handle->_token.size(), con_handle->_key_name ), "now" );

	delete[] buffer;

	auto handler = boost::bind( &Server::waitToken, this, con_handle, boost::asio::placeholders::error );
	boost::asio::async_write( con_handle->socket, boost::asio::buffer( buf ), handler );
}

void Server::waitToken( con_handle_t con_handle, boost::system::error_code const &err )
{
	auto handler = boost::bind( &Server::compareToken, this, con_handle, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred  );
	boost::asio::async_read_until( con_handle->socket, con_handle->read_buffer, "</message>", handler );
}

void Server::compareToken( con_handle_t con_handle, boost::system::error_code const &err, size_t bytes_transfered )
{
	std::cout << "Читаем\n";
	parse( con_handle, bytes_transfered );

	std::string response = con_handle->_parser->getElements( "data" )[0].readAttribute( "content" ).getData( );

	response = Decrypt( response.c_str( ) );

	std::cout << RED << response << "\n" << NONE_FORMAT << std::endl;

	for( int i = 0; i < 48; ++i )
	{
		if( con_handle->_token[i] != response[i] )
		{
			sendAuthenticationResult( con_handle, std::make_shared<std::string>( "ahaahhahahaha not success" ) );
			return ;
		}
	}

	sendAuthenticationResult( con_handle, std::make_shared<std::string>( "Success" ) );

	asyncRead( con_handle );
}

void Server::sendAuthenticationResult(con_handle_t con_handle, std::shared_ptr<std::string> msg)
{
	std::cout << "Sending message\n";

	std::string string_encrypt = "";

	char* msg_encrypt = Encrypt( msg->c_str(), strlen( msg->c_str() ), con_handle->_key_name );
	string_encrypt.append( msg_encrypt );
			
	delete[] msg_encrypt;	

	auto buff = std::make_shared<std::string>( con_handle->_parser->configureString( con_handle->_jid, "", string_encrypt, "сегодня" ) );

	auto handler = boost::bind( &Server::handleWrite, this, con_handle, boost::asio::placeholders::error );
	boost::asio::async_write( con_handle->socket, boost::asio::buffer( *buff ), handler );
}

Server::~Server()
{

}


void Server::startListen( uint16_t port )
{
    auto endpoint = boost::asio::ip::tcp::endpoint( boost::asio::ip::tcp::v4( ), port );
	_acceptor.open( endpoint.protocol( ) );
	_acceptor.set_option( boost::asio::ip::tcp::acceptor::reuse_address( true ) );
	_acceptor.bind( endpoint );
	_acceptor.listen( );
	startAccept( );
}

void Server::handleWrite( con_handle_t con_handle, boost::system::error_code const &err )
{
    if( !err ) 
    {
		std::cout << "Finished sending message\n";
		if( con_handle->socket.is_open( ) ) 
        {
			// Write completed successfully and connection is open
		}
	}
    else 
    {
		std::cerr << "We had an error (write handle): " << err.message( ) << std::endl;
		_connections.erase( con_handle );
	}
}

void Server::handleRead( con_handle_t con_handle, boost::system::error_code const &err, size_t bytes_transfered )
{
    if( bytes_transfered > 0 )
    {
		parse( con_handle, bytes_transfered );

		std::string recipient = con_handle->_parser->getElements( "recipient" )[0].readAttribute( "content" ).getData( );
		std::cout << RED << "Предназначается: " + recipient + NONE_FORMAT + "\n";

		std::string message_data = con_handle->_parser->getElements( "data" )[0].readAttribute( "content" ).getData( );
		std::string full_message = "";

		const long block_size = Crypto::getSizeBlockEncryptHex();

		if( recipient.empty( ) )
		{
			if( block_size == message_data.size( ) )
			{
				char* msg_decrypt = Crypto::Decrypt( message_data.c_str() );
				full_message.append( msg_decrypt, block_size );
				delete[] msg_decrypt;

				int command_id = variatyCommandToServer( full_message );
				switch( command_id )
				{
					case -1:
						std::cout << RED "Ну нет такой комманды" NONE_FORMAT "\n";
					break;
					case 0:
						asyncWrite( con_handle, std::make_shared<std::string>( "~&\t\n\bSuccess disconnect" ), "" );

						_connections.erase( con_handle );
					break;
					case 1:
						std::string full_name = con_handle->_parser->getElements( "sender" )[0].readAttribute( "content" ).getData( );
						size_t ind = full_name.find('@');

						if( ind != std::string::npos )
						{
							con_handle->_key_name = full_name.substr(0, ind);
							con_handle->_jid = full_name;
							
							std::cout << "Sign in from: " + con_handle->_key_name + "\n";
							authentication( con_handle );
							return ;
						}
						else
						{
							std::cerr << "We had an error (read handle): " << err.message( ) << std::endl;
							_connections.erase( con_handle );
						}
					break;
				}
			}
		}
		else
		{
			gostDecrypt( con_handle, message_data.c_str(), full_message );
			std::cout << full_message << std::endl;

			auto connection = findConnection( recipient );

			if( connection != _connections.end() )
			{
				asyncWrite( connection, std::make_shared<std::string>( full_message ), recipient );
			}
		}
	}
	
	if( !err )
    {
		asyncRead( con_handle );
	} 
    else
    {
		std::cerr << "We had an error (read handle): " << err.message( ) << std::endl;
		_connections.erase( con_handle );
	}
}

void Server::handleConnect( con_handle_t con_handle, boost::system::error_code const &err )
{
    if( !err ) 
    {
		asyncRead( con_handle );
	} 
    else 
    {
		std::cerr << "We had an error (handle connect): " << err.message( ) << std::endl;
		_connections.erase( con_handle );
	}
	startAccept( );
}

void Server::asyncRead( con_handle_t con_handle )
{
    auto handler = boost::bind( &Server::handleRead, this, con_handle, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred );
	boost::asio::async_read_until( con_handle->socket, con_handle->read_buffer, "</message>", handler );
}

void Server::asyncWrite( con_handle_t con_handle, std::shared_ptr<std::string> msg, const std::string& recipient )
{
	std::cout << "Sending message\n";

	std::string string_encrypt = "";

	const long int block_size = Crypto::getSizeBlockMessage();
	/*
	for( size_t i = 0; i < strlen( msg->c_str() ); i += block_size )
	{
		char* msg_encrypt = Encrypt( msg->c_str() + i, std::min(strlen( msg->c_str() + i ), (size_t)block_size) );
		string_encrypt.append( msg_encrypt );
			
		delete[] msg_encrypt;
	}
	**/

	gostEncrypt( con_handle, msg->c_str(), msg->size(), string_encrypt );

	auto buff = std::make_shared<std::string>( con_handle->_parser->configureString( con_handle->_jid, recipient, string_encrypt, "сегодня" ) );

	std::cout << "Message send:\n" CYAN + ( *buff) + NONE_FORMAT << std::endl;

	auto handler = boost::bind( &Server::handleWrite, this, con_handle, boost::asio::placeholders::error );
	boost::asio::async_write( con_handle->socket, boost::asio::buffer( *buff ), handler );
}

void Server::startAccept()
{
    auto con_handle = _connections.emplace( _connections.begin( ), _ioservice );
	auto handler = boost::bind( &Server::handleConnect, this, con_handle, boost::asio::placeholders::error );
	_acceptor.async_accept( con_handle->socket, handler );
}

void Server::run()
{
	Crypto::GetC();
    _ioservice.run();
}
#include "client.hpp"

#include "../main.hpp"
#include "../colour.hpp"

#include "../crypto/crypto.hpp"
#include "../parser/xml.hpp"
#include "../math/math.hpp"

#include <thread>
#include <chrono>
#include <time.h>
#include <cstring>


#include <boost/bind.hpp>

#include <X11/Xlib.h>
#include <X11/XKBlib.h> 
#include <X11/extensions/XInput2.h>

#define MULTITHREAD

void printError (std::string error_msg) { std::cout << RED_BOLD "Error: " + error_msg + NONE_FORMAT "\n"; }


Client::Client( const std::string &jid ) : _ioservice( ), _sock( _ioservice )
{
    _parser = std::make_shared<XMLParser>();
    _jid = jid;
    _recipient = _jid;

    _address = jid.substr(jid.find('@') + 1);
    ::printf("%s\n", _address.c_str());
}

Client::~Client( )
{

}

void Client::run( )
{
    _ioservice.run();
}

void Client::connectToServer( )
{
    boost::asio::ip::address addr = 
    boost::asio::ip::address::from_string( _address );
    
    boost::asio::ip::tcp::endpoint ep( addr, 12345 );

    _sock.open( boost::asio::ip::tcp::v4() );
    #ifdef MULTITHREAD
    _sock.async_connect( ep, boost::bind( &Client::handleConnect, this, _1 ) );
    #else
    _sock.connect( ep );
    #endif
}

void Client::handleConnect(const boost::system::error_code &ec)
{
    if( !ec )
    {
        std::cout << "Соединение установлено\n";
    }
    else
    {
        printError( ec.message( ) );
    }
}

void Client::disconnectFromServer()
{
    std::string str = _parser->configureString( _jid, "", "wanttodisconnect", "now" );
    auto buff = std::make_shared<std::string>(str);
    // Start an asynchronous operation to send a heartbeat message.

    auto handler = boost::bind( &Client::handleWrite, this, _1);
    // Start an asynchronous operation to send a heartbeat message.
    boost::asio::async_write(_sock, boost::asio::buffer( *buff ),
        handler);
    asyncRead( );
}

void Client::handleWrite( boost::system::error_code const &err )
{
    std::cout << GREEN_BOLD "Похоже написали" NONE_FORMAT "\n";
    if( !err )
    {
        std::cout << GREEN_BOLD "Success write" NONE_FORMAT "\n";

        std::thread t2( &Client::asyncWrite, this );
        t2.detach( );
    }
    else
    {
        printError( err.message( ) );
    }
}

void Client::handleRead( boost::system::error_code const &err, size_t bytes_transfered )
{
    std::cout << "Чето пришло\n";
    if( !err )
    {
        parse( bytes_transfered );

        std::string full_message = "";

        //std::cout << BLUE "То что парсим " << line + NONE_FORMAT << std::endl;
        auto message = _parser->getElements( "data" )[0].readAttribute( "content" ).getData( );

        const long int block_size = Crypto::getSizeBlockEncryptHex();

        std::string msg_gost_decrypt;
        gostDecrypt( message.c_str(), msg_gost_decrypt );

        /*
        char* msg_decrypt = Decrypt( message.c_str() );

        if( strcmp( msg_decrypt, "~&\t\n\bSuccess disconnect" ) == 0 )
        {
            std::cout << RED_BOLD "Успешно отключились" NONE_FORMAT "\n";
            return ;
        }
        std::cout << BLUE "Message Received on client: " << msg_decrypt << NONE_FORMAT << std::endl;

        full_message.append( msg_decrypt );

        delete[] msg_decrypt;
        */

        //надо чуть позже сделать нормальную историю сообщений
        Message new_message { _parser->getElements( "sender" )[0].readAttribute( "content" ).getData( ), msg_gost_decrypt };
        _message_buffer.push_back( new_message );

        printUI( );
        asyncRead( );
    }
    else
    {
        printError( err.message( ) );
    }
}



void Client::asyncRead( )
{
    std::cout << GREEN << "Start async reading" << NONE_FORMAT << std::endl;
    auto handler = boost::bind( &Client::handleRead, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred );
    // Start an asynchronous operation to read a newline-delimited message.
    boost::asio::async_read_until( _sock, _read_buffer, "</message>", handler );
}

void Client::asyncWrite( )
{
    std::string str;
    std::string full_message;
    std::string encrypt = "";
    int ch;
    while( ( ch = getchar( ) ) != '\n' )
    {
        full_message += ch;
    }


    Message msg{ _recipient, full_message };
    _message_buffer.push_back( msg );

    const long int block_size = Crypto::getSizeBlockMessage( );

    std::string gost_encrypt_msg;
    gostEncrypt( full_message.c_str(), full_message.size(), gost_encrypt_msg );
    str = _parser->configureString( _jid, _recipient, gost_encrypt_msg, "now" );

    std::cout << "Client send:\n"
        + str << std::endl;

    auto buff = std::make_shared<std::string>( str );
    auto handler = boost::bind( &Client::handleWrite, this, boost::asio::placeholders::error );
        // Start an asynchronous operation to send a heartbeat message.
    boost::asio::async_write(_sock, boost::asio::buffer( *buff ),
        handler );    
}

void Client::printUI()
{
    //system( "clear" );

    ::puts( ( GREEN_BOLD "Собеседник: " GREEN + _recipient + NONE_FORMAT ).c_str( ) );
    for( Message msg : _message_buffer )
    {
        ::puts( (BLUE + msg._sender + GREEN ": " + msg._data + NONE_FORMAT).c_str( ) );
    }
}

char *Client::Encrypt(const char *data, size_t size)
{
    return Crypto::Encrypt(data, size);
}

char *Client::Decrypt(const char *data)
{
    return Crypto::Decrypt(data);
}

void Client::gostEncrypt(const char *data, size_t size, std::string& enc_str)
{
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

        Crypto::gost_Encrypt(message, encrypt_message);

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
}

void Client::gostDecrypt(const char *data, std::string& dec_str)
{
    size_t size = strlen(data) / 2;
    char* tmp_data = new char[ strlen(data) / 2 ];
    Math::fromHexToChar(tmp_data, data, strlen(data));

    for( size_t i = 0; i < size; i += BLOCK_SIZE )
    {
        uint8_t* message = new uint8_t[BLOCK_SIZE];
        uint8_t* decrypt_message = new uint8_t[BLOCK_SIZE];

        memcpy(message, tmp_data + i, BLOCK_SIZE);

        Crypto::X(message, iv, message);

        Crypto::gost_Decrypt(message, decrypt_message);

        dec_str.append((char*)decrypt_message);

        delete[] message;
        delete[] decrypt_message;
    }

    delete[] tmp_data;
}

void Client::grabInput( )
{
    /*
    Display *disp = XOpenDisplay(":0");

    int xiOpcode, queryEvent, queryError;
    if (! XQueryExtension(disp, "XInputExtension", &xiOpcode, &queryEvent, &queryError)) 
    { 
        std::cerr << "X Input extension not available" << std::endl; 
        exit(2); 
    } 
    { // Request XInput 2.4, guarding against changes in future versions 
        int major = 2, minor = 0; 
        int queryResult = XIQueryVersion(disp, &major, &minor); 
        if (queryResult == BadRequest) 
        { 
            std::cerr << "Need XI 2.4 support (got " << major << "." << minor << std::endl; 
            exit(3); 
        } 
        else if (queryResult != Success) 
        { 
            std::cerr << "Internal error" << std::endl; 
            exit(4); 
        } 
    }
    
    
    // Register events 
    Window root = DefaultRootWindow(disp); 
    XIEventMask m; 
    m.deviceid = XIAllMasterDevices; 
    m.mask_len = XIMaskLen(XI_LASTEVENT); 
    m.mask = (unsigned char*)calloc(m.mask_len, sizeof(char)); 
    XISetMask(m.mask, XI_RawKeyPress); 
    XISetMask(m.mask, XI_RawKeyRelease); 
    XISelectEvents(disp, root, &m, 1); 
    XSync(disp, false); free(m.mask); 

    while (true) 
    { 
        XEvent event; 
        XGenericEventCookie *cookie = (XGenericEventCookie*)&event.xcookie; 
        XNextEvent(disp, &event); 
        if (XGetEventData(disp, cookie) && cookie->type == GenericEvent && cookie->extension == xiOpcode) 
        { 
            switch (cookie->evtype) 
            { 
                case XI_RawKeyPress: 
                { 
                    XIRawEvent *ev = (XIRawEvent*)cookie->data; 
                    // Ask X what it calls that key 
                    KeySym s = XkbKeycodeToKeysym(disp, ev->detail, 0, 0); 
                    if (NoSymbol == s) continue; 
                    char *str = XKeysymToString(s); 
                    if (NULL == str) continue;
                    if(strstr(str, "F1"))
                    {
                        
                    }

                    

                    break; 
                } 
            } 
        } 


    }*/
}


void Client::choiceRecipient( )
{
    printChoiceRecipientPage( );
    std::cin >> _recipient;
}

void Client::work()
{
    asyncRead();
    asyncWrite();
    //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
}



void Client::parse( size_t bytes_transfered )
{
    std::istream is( &_read_buffer );
    std::string line;
    size_t bytes_read = 0;

    char* msg = new char[ bytes_transfered ];
    is.read( msg, bytes_transfered );
    line.append( msg );
    
    delete[] msg;

    size_t begin = line.find( "<message>" );
    size_t end = line.find( "</message>" ) + strlen( "</message>" );

    if( begin != std::string::npos && end != std::string::npos )
    {
        line = line.substr( begin, end );
        std::cout << "Parse message:\n" GREEN + line + NONE_FORMAT "\n";
        _parser->parseXMLStr( line );
    }
    else
    {
        if(begin == std::string::npos)
        {
            ::puts(RED_BOLD "Чето не находит начало" NONE_FORMAT);
        }
        else
        {
            ::puts(RED_BOLD "Нет конца" NONE_FORMAT);
        }
    }
}

void Client::signIn( )
{
    std::string str = "signInRequest";
    str = Encrypt( str.c_str(), str.size() );
    str = _parser->configureString( _jid, "", str, "now" );

    auto buff = std::make_shared<std::string>(str);
    

    boost::asio::write( _sock, boost::asio::buffer( *buff ) );  
    ::puts("Write request");  
#ifdef MULTITHREAD
    auto handler = boost::bind( &Client::requestSignIn, this, _1, _2 );
    boost::asio::async_read_until( _sock, _read_buffer, "</message>", handler );

#else
    boost::asio::read_until( _sock, _read_buffer, "</message>" );
    ::puts("read async call"); 
    parse( 2000 );
        str = Decrypt( _parser->getElements( "data" )[0].readAttribute( "content" ).getData( ).c_str( ) );

        std::cout << str + "\n";

        str = Encrypt( str.c_str(), str.size() );
        str = _parser->configureString( _jid, "", str, "now" );

        buff = std::make_shared<std::string>( str );
        std::cout << GREEN << "Receiving sign in results..." << NONE_FORMAT << std::endl;
        //auto handler = boost::bind( &Client::receiveSignInResult, this, boost::asio::placeholders::error );

        boost::asio::write( _sock, boost::asio::buffer( *buff ) );
        boost::asio::read_until( _sock, _read_buffer, "</message>" );
    parse( _read_buffer.size() );

    std::string result = _parser->getElements( "data" )[0].readAttribute( "content" ).getData( );

    std::string result_decrypt = Decrypt( result.c_str() );

    std::cout << "Result: " + result_decrypt + "\n";

    if( result_decrypt == "Success" )
    {
        std::cout << GREEN_BOLD "Всё отлично, проходим" NONE_FORMAT "\n";
        bAuthorized = true;
    }
    else
    {
        std::cout << RED_BOLD "Ошибка аутентификации" NONE_FORMAT "\n";
        exit( 1 );
    }
#endif
}

void Client::requestSignIn( boost::system::error_code const &err, size_t bytes_transfered  )
{
    ::puts("Read complete");  
    if( !err )
    {
        parse( bytes_transfered );
        std::string str = Decrypt( _parser->getElements( "data" )[0].readAttribute( "content" ).getData( ).c_str( ) );

        std::cout << str + "\n";

        for(int i = 0; i < 32; ++i)
        {
            session_key[i] = str[i];
        }
        for(int i = 32; i < 48; ++i)
        {
            iv[i - 32] = str[i];
        }

        Crypto::ExpandKey(session_key);
        const char* da = "da";
        std::string test = "";
        std::string test2 = "";

        gostEncrypt(da, strlen(da), test);
        std::cout << test << std::endl;
        gostDecrypt(test.c_str(), test2);

        std::cout << test2 << std::endl;

        str = Encrypt( str.c_str(), str.size() );
        str = _parser->configureString( _jid, "", str, "now" );
        
        auto buff = std::make_shared<std::string>( str );
        std::cout << GREEN << "Receiving sign in results..." << NONE_FORMAT << std::endl;
        auto handler = boost::bind( &Client::receiveSignInResult, this, boost::asio::placeholders::error );

        boost::asio::async_write( _sock, boost::asio::buffer( *buff ), handler );
    }
    else
    {
        printError( err.message( ) );
    }
}

void Client::receiveSignInResult( boost::system::error_code const &err )
{
    std::cout << "receiveSignInResult\n";
    boost::asio::read_until( _sock, _read_buffer, "</message>" );
    parse( _read_buffer.size() );

    std::string result = _parser->getElements( "data" )[0].readAttribute( "content" ).getData( );

    std::string result_decrypt = Decrypt( result.c_str() );

    std::cout << "Result: " + result_decrypt + "\n";

    if( result_decrypt == "Success" )
    {
        std::cout << GREEN_BOLD "Всё отлично, проходим" NONE_FORMAT "\n";
        bAuthorized = true;
        work();
    }
    else
    {
        std::cout << RED_BOLD "Ошибка аутентификации" NONE_FORMAT "\n";
        exit( 1 );
    }
}

void Client::printChoiceRecipientPage()
{
    system( "clear" );

    ::puts("Введите кому будете писать: ");
}



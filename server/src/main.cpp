#include "main.hpp"

#include "colour.hpp"

#include "server/server.hpp"
#include "math/math.hpp"
#include "parser/xml.hpp"
#include "crypto/crypto.hpp"

#include <thread>
#include <cstring>

#define PHONE "192.168.132.34"
#define LOCAL "127.0.0.1"
#define HOME "192.168.0.10"

void clearInputBuffer()
{
    std::cin.clear(); // Сбрасываем флаг ошибки ввода
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Игнорируем все символы до символа новой строки
}

void EchoMode(int EchoOn)
{
    struct termios TermConf;

    tcgetattr(STDIN_FILENO, &TermConf);

    if(EchoOn)
        TermConf.c_lflag |= (ICANON | ECHO);
    else
        TermConf.c_lflag &= ~(ICANON | ECHO);

    tcsetattr(STDIN_FILENO, TCSANOW, &TermConf);
}


int main()
{
    Crypto::Configure();
    //Crypto::GenerateKeys();
    //puts("Всё норм");
    Server* srv= new Server( );
	srv->startListen( 12345 );
    
	srv->run( );
}
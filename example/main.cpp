#include <iostream>
#include "api/c_auth.hpp"
#include "Protection/anti_hook.hpp"
#include "Protection/debugger_detect.hpp"
#include "helper.h"
#include <thread>

/*Please watch https://youtu.be/WS8sLlfu4Go before you ask any questions about the Setup*/



void watermark() {
    system("cls");
    std::cout << skCrypt("--> BigC The Best <--") << std::endl;
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[25];

    strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

    return std::string(buffer);
}

BigC_auth::api auth_instance(c_xor("VERSION"), c_xor("PROGRAM KEY"), c_xor("API KEY"));



void start()
{

    //your code after login
   
}

int main()
{
    SetConsoleTitleA(skCrypt("BigC Auth C++")); // Console title you can change

    std::thread antidebug(Protect);// protection

    int option; // the options

    std::string user, email, pass, token; // some basic stuffs

    auth_instance.init(); // init auth

    safe();

    system("color a");
    std::cout << skCrypt("Connected to Server !");
    Sleep(5000);
    system("cls");

    std::cout << skCrypt(" \n [1] Login\n [2] Register\n [3] Renew\n [4] All in one\n\n Your Option : "); //select your stuff [Login , Register , Renew] //
    std::cin >> option;

    notSafe();

    switch (option) {
    case 1:
        safe();
        system("cls");
        std::cout << skCrypt("Username : ");
        std::cin >> user;


        system("cls");
        std::cout << skCrypt("Password : ");
        std::cin >> pass;
         
        notSafe();

        system("cls");
        if (auth_instance.login(user, pass)) {

            safe();

            std::cout << skCrypt("Welcome\n");

            std::cout << skCrypt("Expire in :\n");
            std::cout << tm_to_readable_time(auth_instance.user_data.expires) << std::endl;
            Sleep(5000); /*Only if you want:)*/
            start();
        }
        else {
            std::cout << skCrypt("Credentials invalid");
        }
        break;

    case 2:

        safe();

        system("cls");
        std::cout << skCrypt("Username : ");
        std::cin >> user;
        system("cls");
        std::cout << skCrypt("Email : ");
        std::cin >> email;
        system("cls");
        std::cout << skCrypt("Password : ");
        std::cin >> pass;
        system("cls");
        std::cout << skCrypt("License : ");
        std::cin >> token;

        system("cls");

        notSafe();

        if (auth_instance.register(user, email, pass, token))
            std::cout << skCrypt("Registered Successfully!!");

        else
            std::cout << skCrypt("Failed");

        break;

    case 3:

        safe();

        system("cls");
        std::cout << skCrypt("Username : ");
        std::cin >> user;

        system("cls");
        std::cout << skCrypt("License : ");
        std::cin >> token;

        system("cls");

        notSafe();

        if (auth_instance.activate(user, token))
            std::cout << skCrypt("Activated Successfully!!");

        else
            std::cout << skCrypt("Contact the Owner");

        break;

    case 4:

        safe();

        std::cout << skCrypt("License Key : ");
        std::cin >> token;

        notSafe();

        if (auth_instance.all_in_one(token)) {
            std::cout << skCrypt("Logged in Successfully !!!\n");

            std::cout << auth_instance.user_data.username << std::endl;
            std::cout << auth_instance.user_data.email << std::endl;
            std::cout << tm_to_readable_time(auth_instance.user_data.expires) << std::endl;
            std::cout << auth_instance.user_data.var << std::endl;
            std::cout << auth_instance.user_data.rank << std::endl;
            Sleep(5000); /*Only if you want:)*/
            start();
        }
        else {
            std::cout << skCrypt("Invalid Selection");
        }
        break;

    default:

        std::cout << skCrypt("Invalid Selection\n");
        break;
    }

    std::cin >> option;
}



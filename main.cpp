#include <iostream>
#include "api/c_auth.hpp"
#include "Protection/anti_hook.hpp"
#include "Protection/debugger_detect.hpp"
#include "mapper/intel_driver.hpp"
#include "mapper/kdmapper.hpp"


/*Please watch https://youtu.be/WS8sLlfu4Go before you ask any questions about the Setup*/



void watermark() {
    system("cls"); 
    std::cout << "--> BigC The Best <--" << std::endl;
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[25];

    strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

    return std::string(buffer);
}

BigC_auth::api auth_instance(c_xor("VERSION"), c_xor("PROGRAM KEY"), c_xor("API KEY"));


void Protect() {


    while (true) {


        //this should block some dll injections, ofcause u can add more modules 
        //the anti debug should block most attempts to attach your process to a debugger 



        unhook(skCrypt("ntdll.dll"));

        unhook(skCrypt("kernel32.dll"));

        unhook(skCrypt("user32.dll"));


        if (check_remote_debugger_present_api() != 0)
        {
            MessageBoxA(0, "Debugger found", "BigC", MB_ICONERROR | MB_OK);
            exit(0);
        }

        if (nt_query_information_process_debug_flags() != 0)
        {
            MessageBoxA(0, "Debugger found", "BigC", MB_ICONERROR | MB_OK);
            exit(0);
        }

        if (nt_query_information_process_debug_object() != 0)
        {
            MessageBoxA(0, "Debugger found", "BigC", MB_ICONERROR | MB_OK);
            exit(0);
        }

        if (titanhide() != 0)
        {
            MessageBoxA(0, "TitanHide found", "BigC", MB_ICONERROR | MB_OK);
            exit(0);
        }


    }
}


void start()
{


    //this only works with the premium subscribtion
    //this loads the driver through bytes which means it will never hit the disk drive

    std::cout << skCrypt("Loading Driver.... ");


    std::vector<std::uint8_t> test = auth_instance.file("");

    HANDLE iqvw64e_device_handle = intel_driver::Load();

    if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
    {
        std::cout << skCrypt("Please disable your anti-virus");
        Sleep(3500);
        exit(0);
    }

    if (!kdmapper::MapDriver(iqvw64e_device_handle, test.data()))
    {
        std::cout << skCrypt("Please disable anti-cheats like faceit and valorant");
        
        Sleep(3500);
        exit(0);
    }

    intel_driver::Unload(iqvw64e_device_handle);


    std::cout << skCrypt("Driver loaded Succesfully");
}

int main()
{
    SetConsoleTitleA("BigC Auth C++"); // Console title you can change

    std::thread antidebug(Protect);// protection

    int option; // the options

    std::string user, email, pass, token; // some basic stuffs

    auth_instance.init(); // init auth

    system("color a");
    std::cout << "Connected to Server !";
    Sleep(5000);
    system("cls");

    std::cout << " \n [1] Login\n [2] Register\n [3] Renew\n [4] All in one\n\n Your Option : "; //select your stuff [Login , Register , Renew] //
    std::cin >> option;

    switch (option) {
    case 1:
        system("cls");
        std::cout << "Username : ";
        std::cin >> user;
         

        system("cls");
        std::cout << "Password : ";
        std::cin >> pass;

        system("cls");
        if (auth_instance.login(user, pass)) {
            
            std::cout << "Welcome\n";

            std::cout << "Expire in :\n";
            std::cout << tm_to_readable_time(auth_instance.user_data.expires) << std::endl;
            Sleep(5000); /*Only if you want:)*/
            start();
        }
        else {
            std::cout << "Credentials invalid";
        }
        break;

    case 2:
        system("cls");
        std::cout << "Username : ";
        std::cin >> user;
        system("cls");
        std::cout << "Email : ";
        std::cin >> email;
        system("cls");
        std::cout << "Password : ";
        std::cin >> pass;
        system("cls");
        std::cout << "License : ";
        std::cin >> token;

        system("cls");
        if (auth_instance.register(user, email, pass, token))
            std::cout << "Registered Successfully!!";

        else
            std::cout << "Failed";

        break;

    case 3:
        system("cls");
        std::cout << "Username : ";
        std::cin >> user;

        system("cls");
        std::cout << "License : ";
        std::cin >> token;

        system("cls");
        if (auth_instance.activate(user, token))
            std::cout << "Activated Successfully!!";

        else
            std::cout << "Contact the Owner";

        break;

    case 4:

        std::cout << "License Key : ";
        std::cin >> token;


        if (auth_instance.all_in_one(token)) {
            std::cout << "Logged in Successfully !!!\n";

            std::cout << auth_instance.user_data.username << std::endl;
            std::cout << auth_instance.user_data.email << std::endl;
            std::cout << tm_to_readable_time(auth_instance.user_data.expires) << std::endl;
            std::cout << auth_instance.user_data.var << std::endl;
            std::cout << auth_instance.user_data.rank << std::endl;
            Sleep(5000); /*Only if you want:)*/
            start();
        }
        else {
            std::cout << "Invalid Selection";
        }
        break;

    default:

        std::cout << "Invalid Selection\n";
        break;
    }

    std::cin >> option;
}



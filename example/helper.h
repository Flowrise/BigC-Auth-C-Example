#pragma once
#include <iostream>
#include <windows.h>
#include "Protection/anti_hook.hpp"
#include "Protection/debugger_detect.hpp"
#include "xorstr.hpp"
void* pe_header[4096];
// enable antidump
void safe()
{
	
	DWORD old = 0;
	void* module = GetModuleHandleW(0);

	VirtualProtect(module, 4096, PAGE_READWRITE, &old);
	memcpy(pe_header, module, 4096);
	ZeroMemory(module, 4096);
	VirtualProtect(module, 4096, old, &old);
	
}
void notSafe()
{
	
	DWORD old = 0;
	void* module = GetModuleHandleW(0);

	VirtualProtect(module, 4096, PAGE_READWRITE, &old);
	memcpy(module, pe_header, 4096);
	VirtualProtect(module, 4096, old, &old);
	
}



void Protect() {


    while (true) {


        //this should block some dll injections, ofcause u can add more modules 
        //the anti debug should block most attempts to attach your process to a debugger 



        unhook(XorStr("ntdll.dll").c_str());

        unhook(XorStr("kernel32.dll").c_str());

        unhook(XorStr("user32.dll").c_str());


        if (check_remote_debugger_present_api() != 0)
        {
            MessageBoxA(0, (XorStr("Debugger found").c_str()), (XorStr("BigC").c_str()), MB_ICONERROR | MB_OK);
            exit(0);
        }

        if (nt_query_information_process_debug_flags() != 0)
        {
            MessageBoxA(0, (XorStr("Debugger found").c_str()), (XorStr("BigC").c_str()), MB_ICONERROR | MB_OK);
            exit(0);
        }

        if (nt_query_information_process_debug_object() != 0)
        {
            MessageBoxA(0, (XorStr("Debugger found").c_str()), (XorStr("BigC").c_str()), MB_ICONERROR | MB_OK);
            exit(0);
        }

        if (titanhide() != 0)
        {
            MessageBoxA(0, (XorStr("TitanHide found").c_str()), (XorStr("BigC").c_str()), MB_ICONERROR | MB_OK);
            exit(0);
        }


    }
}
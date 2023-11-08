#pragma once

//#define CONSOLE

#ifdef CONSOLE  
#define printfdbg printf  
#else  
#define printfdbg(...)      
#endif  
#include "resource.h"   
using namespace std;
 
#include <Windows.h>
#include <fstream> 
#include <vector>
#include <string> 
#include <tlhelp32.h> 
#include <sstream> 
#define ReCa reinterpret_cast

typedef struct {
	PBYTE imageBase;
	HMODULE(WINAPI* loadLibraryA)(PCSTR);
	FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
} LoaderData;

int FindProcByName(wchar_t* processname);
uintptr_t GetModuleBaseEx(DWORD procId, const char* modName);
uintptr_t GetProcAddressEx(HANDLE hProcess, uintptr_t moduleBase, const char* function);
uintptr_t WINAPI loadLibrary(LoaderData* loaderData);
void stub();

int rvm(HANDLE hProcess, PVOID addr, int num, void* buf);

BOOL ComparePattern(HANDLE pHandle, DWORD address, char* pattern, char* mask);
DWORD ExternalAoBScan(HANDLE pHandle, DWORD moduleBase, char* pattern, char* mask);
uintptr_t MyLoadLibrary(HANDLE hProcess, char* dx_binary);

bool NopMemory(HANDLE hProcess, DWORD addr, size_t size);
char* GetLastErrorAsText();
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
);

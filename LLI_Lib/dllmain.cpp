#include <Windows.h>
#include <iostream> 
using namespace std;
#include <Psapi.h> 
#include "detours.h"
#pragma comment(lib, "detours.lib") 
#include <winternl.h>

struct pass_args 
{ 
    bool havemodule = false;
    wchar_t modules[MAX_PATH]; 
};
bool havemodule = false;
bool pauseEveryModule = false;
wchar_t modules[MAX_PATH];
  
#define CONSOLE 
 
#ifdef CONSOLE
#define printfdbg printf
#else
#define printfdbg(...)
#endif
  
HMODULE myhModule;

// helper functions and macros for parsing PE headers
#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD))
#define OPTHDROFFSET(ptr) ((LPVOID)((BYTE *)(ptr)+((PIMAGE_DOS_HEADER)(ptr))->e_lfanew+SIZE_OF_NT_SIGNATURE+sizeof(IMAGE_FILE_HEADER)))
LPVOID  WINAPI GetModuleEntryPoint(
    LPVOID    lpFile)
{
    PIMAGE_OPTIONAL_HEADER   poh;
    poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(lpFile);
    return poh == NULL ? NULL : (LPVOID)poh->AddressOfEntryPoint;
}

#define NT_SUCCESS(x) ((x) >= 0)
typedef NTSTATUS(NTAPI* pLdrLoadDll)(_In_opt_ UINT32 Flags, _In_opt_ PUINT32 Reserved, PUNICODE_STRING DllName, PVOID* BaseAddress);
pLdrLoadDll NtLdrLoadDll = (pLdrLoadDll)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
 
int needPause = 0;
NTSTATUS __stdcall hkLdrLoadDll(UINT32 Flags, PUINT32 Reserved, PUNICODE_STRING DllName, PVOID* BaseAddress)
{
    HMODULE hDll = 0;

    //return if already loaded 
    //if (hDll = GetModuleHandleW(DllName->Buffer))  return NtLdrLoadDll(Flags, Reserved, DllName, BaseAddress);

    if (pauseEveryModule && (!wcsstr(DllName->Buffer, L"ntdll.dll")) && (!wcsstr(DllName->Buffer, L"apphelp.dll")))
    {
        printfdbg("NtLdrLoadDll %ls\n", DllName->Buffer);
        system("pause"); 
    }
    
    bool foundModule = false;
    if (havemodule && wcsstr(DllName->Buffer, modules))
    {
        needPause = (int)GetCurrentThread(); foundModule = true;
    }
        
    NTSTATUS ret = NtLdrLoadDll(Flags, Reserved, DllName, BaseAddress);
   
    if (hDll = GetModuleHandleW(DllName->Buffer))
    {  
        printfdbg("%sLoaded: %ls -> EntryPoint %x+%x\n", foundModule ? ">> " : "", DllName->Buffer, hDll, GetModuleEntryPoint(hDll));
    }
   
    return ret;
}

#include <tlhelp32.h>
char* GetModuleOfAddress(DWORD address) {
    MODULEENTRY32 me32 = { 0 };
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    me32.dwSize = sizeof(MODULEENTRY32); 
    if (Module32First(hModuleSnap, &me32))
    {
        do
        { 
            DWORD modEnd = (DWORD)me32.modBaseAddr + (DWORD)me32.modBaseSize;
            if (address >= (DWORD)me32.modBaseAddr && address <= modEnd) {
                return me32.szModule;
            }
        } while (Module32Next(hModuleSnap, &me32));
    } 
    return (char*)""; 
}

typedef NTSTATUS(NTAPI* ZwCreateThreadEx_t) (    OUT PHANDLE hThread,    IN ACCESS_MASK DesiredAccess,    IN PVOID ObjectAttributes,    IN HANDLE ProcessHandle,    IN PVOID lpStartAddress,    IN PVOID lpParameter,    IN ULONG Flags,    IN SIZE_T StackZeroBits,    IN SIZE_T SizeOfStackCommit,    IN SIZE_T SizeOfStackReserve,    OUT LPVOID lpBytesBuffer);
ZwCreateThreadEx_t _NtCreateThreadEx = (ZwCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

NTSTATUS __stdcall hkCreateThreadEx(
    OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress,    IN PVOID lpParameter,    IN ULONG Flags,    IN SIZE_T StackZeroBits,    IN SIZE_T SizeOfStackCommit,    IN SIZE_T SizeOfStackReserve,    OUT LPVOID lpBytesBuffer)
{ 
    //char* ModuleName = GetModuleOfAddress((DWORD)lpStartAddress); 
    if (needPause == (int)GetCurrentThread()) {
    //    printfdbg("_NtCreateThreadEx %s: %x \n", ModuleName, lpStartAddress);
        system("pause"); 
        needPause = 0;
    } 
     
    return _NtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress,
        lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
}

DWORD WINAPI InitFunc() {

#ifdef CONSOLE
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    printfdbg("loadlibrary Interception\n"); 
#endif 
      
    if (havemodule)
        printfdbg("Module %ls\n", modules);
    printfdbg("NtLdrLoadDll %x\n", NtLdrLoadDll);
    printfdbg("NtCreateThreadEx %x\n", _NtCreateThreadEx); 
    printfdbg("=========================\n");

    NtLdrLoadDll = (pLdrLoadDll)DetourFunction((PBYTE)NtLdrLoadDll, (PBYTE)hkLdrLoadDll);
    _NtCreateThreadEx = (ZwCreateThreadEx_t)DetourFunction((PBYTE)_NtCreateThreadEx, (PBYTE)hkCreateThreadEx);
   
    while (1) { 
        Sleep(10);
        if (GetAsyncKeyState(VK_DELETE))  break;
    }

#ifdef CONSOLE
    fclose(fp);
    FreeConsole();
#endif
     
    Beep(600, 400); 

    DetourRemove(reinterpret_cast<BYTE*>(NtLdrLoadDll), reinterpret_cast<BYTE*>(hkLdrLoadDll));
    DetourRemove(reinterpret_cast<BYTE*>(_NtCreateThreadEx), reinterpret_cast<BYTE*>(hkCreateThreadEx));

    Sleep(100);
    FreeLibraryAndExitThread(myhModule, 0);
     
    return 0;
}

extern "C" __declspec(dllexport) int InitFn(pass_args * argumento)
{ 
    havemodule = argumento->havemodule;
    if (havemodule)
    {
        memcpy(modules, argumento->modules, MAX_PATH); 
        if (wcsstr(modules, L"pauseeverymodule"))
            pauseEveryModule = true;
    } 
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitFunc, NULL, 0, NULL);
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        myhModule = hModule; 
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
 

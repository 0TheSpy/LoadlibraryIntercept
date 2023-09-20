// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <iostream>
#include <vector>
using namespace std;
#include "detours.h"
#pragma comment(lib, "detours.lib") 
#include <cstddef>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <shellapi.h>
#pragma comment(lib, "wbemuuid.lib") 
#include <Wbemidl.h> 
#include <tchar.h>
#include <stdio.h>
#include <string>  
#include <Psapi.h>  
#include <winternl.h>
#include <tlhelp32.h>
#include "ioapiset.h"
#include <winioctl.h> 
#include <assert.h>
#include <random>
#include <ntddscsi.h>

struct pass_args
{
    bool havemodule = false;
    bool hwidspoof = false;
    wchar_t modules[MAX_PATH];
#ifdef HWID
    DWORD targethwid;
#endif 
};
bool havemodule = false;
bool hwidspoof = false;
bool pauseEveryModule = false;
wchar_t modules[MAX_PATH];

#define CONSOLE 
#ifdef CONSOLE
#define printfdbg printf
#else
#define printfdbg(...)
#endif

vector<HANDLE> handleslist;

DWORD GetAddressFromSignature(vector<int> signature, DWORD startaddress = 0, DWORD endaddress = 0)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (startaddress == 0) {
        startaddress = (DWORD)(si.lpMinimumApplicationAddress);
    }
    if (endaddress == 0) {
        DWORD endaddress = (DWORD)(si.lpMaximumApplicationAddress);
    }

    MEMORY_BASIC_INFORMATION mbi{ 0 };
    DWORD protectflags = (PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS);

    for (DWORD i = startaddress; i < endaddress - signature.size(); i++)
    {
        //cout << "scanning: " << hex << i << endl;
        if (VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi))) {
            if (mbi.Protect & protectflags || !(mbi.State & MEM_COMMIT)) {
#ifdef DEBUG
                //cout << "Bad Region! Region Base Address: " << mbi.BaseAddress << " | Region end address: " << hex << (int)((DWORD)mbi.BaseAddress + mbi.RegionSize) << endl;
#endif
                i = (DWORD)mbi.BaseAddress + mbi.RegionSize - 1;
                continue; //if bad address then dont read from it
            }
#ifdef DEBUG
            // cout << "Good Region! Region Base Address: " << mbi.BaseAddress << " | Region end address: " << hex << (int)((DWORD)mbi.BaseAddress + mbi.RegionSize) << endl;
#endif
            for (DWORD k = (DWORD)mbi.BaseAddress; k < (DWORD)mbi.BaseAddress + mbi.RegionSize - signature.size(); k++) {
                for (DWORD j = 0; j < signature.size(); j++) {
                    if (signature.at(j) != -1 && signature.at(j) != *(unsigned char*)(k + j)) //byte
                        break;
                    if (j + 1 == signature.size())
                        if (k % 0x0800 == 0)
                            return k;
                        else
                        {
#ifdef DEBUG
                            // cout << k << " isn't correct\n";
#endif
                            break;
                        }
                }
            }
            i = (DWORD)mbi.BaseAddress + mbi.RegionSize - 1;
        }
    }
    return NULL;
}

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

bool isQueryHooked = false;

typedef int(__stdcall* myFunction)(int a1, int a2, int a3, int a4, int a5, int a6, int a7);
myFunction mFunc;

const wchar_t fakeQuery[] = L"\0";
wchar_t* strQuery;
__declspec(naked) void hkExecQuery(int a1, int a2, int a3, int a4, int a5, int a6, int a7)
{
    __asm push eax
    __asm mov eax, [esp + 0x10]
        __asm mov strQuery, eax
    __asm pop eax

    printfdbg("ExecQuery %ls\n", strQuery);
     
    if (wcsstr(strQuery, L"Win32_DiskDrive")  
        || wcsstr(strQuery, L"Win32_SCSIController") 
        || wcsstr(strQuery, L"Win32_IDEController")
        || wcsstr(strQuery, L"Win32_PnPSignedDriver"))
        memcpy(strQuery, fakeQuery, sizeof(fakeQuery));

    __asm jmp mFunc
}

#define NT_SUCCESS(x) ((x) >= 0)
typedef NTSTATUS(NTAPI* pLdrLoadDll)(_In_opt_ UINT32 Flags, _In_opt_ PUINT32 Reserved, PUNICODE_STRING DllName, PVOID* BaseAddress);
pLdrLoadDll NtLdrLoadDll = (pLdrLoadDll)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");

int needPause = 0;
NTSTATUS __stdcall hkLdrLoadDll(UINT32 Flags, PUINT32 Reserved, PUNICODE_STRING DllName, PVOID* BaseAddress)
{
    HMODULE hDll = 0;

    if (pauseEveryModule && (!wcsstr(DllName->Buffer, L"ntdll.dll")) && (!wcsstr(DllName->Buffer, L"apphelp.dll")))
    {
        printfdbg("NtLdrLoadDll %ls\n", DllName->Buffer);
        system("pause");
    }

    bool foundModule = false;
    if (havemodule && wcsstr(DllName->Buffer, modules))
    {
        needPause = (int)GetCurrentThreadId(); foundModule = true;
    }

    NTSTATUS ret = NtLdrLoadDll(Flags, Reserved, DllName, BaseAddress);

    if (hDll = GetModuleHandleW(DllName->Buffer))
    {
        if (!hwidspoof)
            printfdbg("%s Loaded: %ls -> EntryPoint %x+%x | Thread %x\n", foundModule ? ">> " : "", DllName->Buffer, hDll, GetModuleEntryPoint(hDll), GetCurrentThreadId());
    }

    if (wcsstr(DllName->Buffer, L"fastprox.dll") && hwidspoof)
    {
        if (isQueryHooked == false) {
            isQueryHooked = true;

            DWORD pExecQuery = 0x160 + (DWORD)GetProcAddress(GetModuleHandleW(DllName->Buffer), "?CreateLimitedRepresentation@CInstancePart@@QAEPAEPAVCLimitationMapping@@HPAE@Z");
            mFunc = (myFunction)DetourFunction((PBYTE)(pExecQuery), (PBYTE)hkExecQuery);
            printfdbg("fastprox.dll hooked! ExecQuery: %x\n", pExecQuery);
        }
    }

    return ret;
}

wchar_t* GetModuleOfAddress(DWORD address) {
    MODULEENTRY32W me32 = { 0 };
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    me32.dwSize = sizeof(MODULEENTRY32W);
    if (Module32FirstW(hModuleSnap, &me32))
    {
        do
        {
            DWORD modEnd = (DWORD)me32.modBaseAddr + (DWORD)me32.modBaseSize;
            if (address >= (DWORD)me32.modBaseAddr && address <= modEnd) {
                return me32.szModule;
            }
        } while (Module32NextW(hModuleSnap, &me32));
    }
    return (wchar_t*)L"";
}

typedef NTSTATUS(NTAPI* pLdrUnloadDll)(HMODULE hModule);
pLdrUnloadDll NtLdrUnloadDll = (pLdrUnloadDll)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrUnloadDll");
NTSTATUS __stdcall hkLdrUnloadDll(HMODULE hModule)
{
    wchar_t* modName = GetModuleOfAddress((DWORD)hModule);
    if (!hwidspoof)
        printfdbg("Unloading %x %ls\n", hModule, GetModuleOfAddress((DWORD)hModule));
    return NtLdrUnloadDll(hModule);
}

typedef NTSTATUS(NTAPI* ZwCreateThreadEx_t) (OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT LPVOID lpBytesBuffer);
ZwCreateThreadEx_t _NtCreateThreadEx = (ZwCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
NTSTATUS __stdcall hkCreateThreadEx(
    OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT LPVOID lpBytesBuffer)
{
    //printfdbg("_NtCreateThreadEx pause? %d -> %x SA %x\n", needPause, GetCurrentThreadId(), lpStartAddress);
    if (needPause == (int)GetCurrentThreadId()) {
        system("pause");
        needPause = 0;
    }

    return _NtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress,
        lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
}

static void Fill(char* Buffer, SIZE_T Length = 0) {
    if (!Length)
        Length = strlen(Buffer);
    srand(time(0));
    for (int i = 0; i < Length; i++) {
        if (Buffer[i] != '\0') {
            if (Buffer[i] > '0' && Buffer[i] <= '9') {
                Buffer[i] = (char)(0x30 + rand() % 9);
            }
            if (Buffer[i] >= 'A' && Buffer[i] <= 'Z') {
                Buffer[i] = (char)(0x41 + rand() % 25);
            }
            if (Buffer[i] >= 'a' && Buffer[i] <= 'z') {
                Buffer[i] = (char)(0x61 + rand() % 25);
            }
        }
    }
}

typedef struct _IDINFO
{
    USHORT  wGenConfig;
    USHORT  wNumCyls;
    USHORT  wReserved2;
    USHORT  wNumHeads;
    USHORT  wReserved4;
    USHORT  wReserved5;
    USHORT  wNumSectorsPerTrack;
    USHORT  wVendorUnique[3];
    CHAR    sSerialNumber[20];
    USHORT  wBufferType;
    USHORT  wBufferSize;
    USHORT  wECCSize;
    CHAR    sFirmwareRev[8];
    CHAR    sModelNumber[40];
    USHORT  wMoreVendorUnique;
    USHORT  wReserved48;
    struct {
        USHORT  reserved1 : 8;
        USHORT  DMA : 1;
        USHORT  LBA : 1;
        USHORT  DisIORDY : 1;
        USHORT  IORDY : 1;
        USHORT  SoftReset : 1;
        USHORT  Overlap : 1;
        USHORT  Queue : 1;
        USHORT  InlDMA : 1;
    } wCapabilities;
    USHORT  wReserved1;
    USHORT  wPIOTiming;
    USHORT  wDMATiming;
    struct {
        USHORT  CHSNumber : 1;
        USHORT  CycleNumber : 1;
        USHORT  UnltraDMA : 1;
        USHORT  reserved : 13;
    } wFieldValidity;
    USHORT  wNumCurCyls;
    USHORT  wNumCurHeads;
    USHORT  wNumCurSectorsPerTrack;
    USHORT  wCurSectorsLow;
    USHORT  wCurSectorsHigh;
    struct {
        USHORT  CurNumber : 8;
        USHORT  Multi : 1;
        USHORT  reserved1 : 7;
    } wMultSectorStuff;
    ULONG  dwTotalSectors;
    USHORT  wSingleWordDMA;
    struct {
        USHORT  Mode0 : 1;
        USHORT  Mode1 : 1;
        USHORT  Mode2 : 1;
        USHORT  Reserved1 : 5;
        USHORT  Mode0Sel : 1;
        USHORT  Mode1Sel : 1;
        USHORT  Mode2Sel : 1;
        USHORT  Reserved2 : 5;
    } wMultiWordDMA;
    struct {
        USHORT  AdvPOIModes : 8;
        USHORT  reserved : 8;
    } wPIOCapacity;
    USHORT  wMinMultiWordDMACycle;
    USHORT  wRecMultiWordDMACycle;
    USHORT  wMinPIONoFlowCycle;
    USHORT  wMinPOIFlowCycle;
    USHORT  wReserved69[11];
    struct {
        USHORT  Reserved1 : 1;
        USHORT  ATA1 : 1;
        USHORT  ATA2 : 1;
        USHORT  ATA3 : 1;
        USHORT  ATA4 : 1;
        USHORT  ATA5 : 1;
        USHORT  ATA6 : 1;
        USHORT  ATA7 : 1;
        USHORT  ATA8 : 1;
        USHORT  ATA9 : 1;
        USHORT  ATA10 : 1;
        USHORT  ATA11 : 1;
        USHORT  ATA12 : 1;
        USHORT  ATA13 : 1;
        USHORT  ATA14 : 1;
        USHORT  Reserved2 : 1;
    } wMajorVersion;
    USHORT  wMinorVersion;
    USHORT  wReserved82[6];
    struct {
        USHORT  Mode0 : 1;
        USHORT  Mode1 : 1;
        USHORT  Mode2 : 1;
        USHORT  Mode3 : 1;
        USHORT  Mode4 : 1;
        USHORT  Mode5 : 1;
        USHORT  Mode6 : 1;
        USHORT  Mode7 : 1;
        USHORT  Mode0Sel : 1;
        USHORT  Mode1Sel : 1;
        USHORT  Mode2Sel : 1;
        USHORT  Mode3Sel : 1;
        USHORT  Mode4Sel : 1;
        USHORT  Mode5Sel : 1;
        USHORT  Mode6Sel : 1;
        USHORT  Mode7Sel : 1;
    } wUltraDMA;
    USHORT    wReserved89[167];
} IDINFO, * PIDINFO;

typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING	Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

wchar_t* GetHandleTypeName(HANDLE hHandle)
{
    typedef NTSTATUS(NTAPI* NtQueryObjectPtr)(
        HANDLE Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength);
    HMODULE hMod = LoadLibrary(_T("NtDll.dll"));
    NtQueryObjectPtr QueryObj = (NtQueryObjectPtr) ::GetProcAddress(hMod, "NtQueryObject");
    assert(QueryObj);
    ULONG OutSize = 0;
    NTSTATUS NtStatus = QueryObj(hHandle, OBJECT_INFORMATION_CLASS(1), NULL, 0, &OutSize);
    std::vector<BYTE> buffer(OutSize);
    PVOID TypeInfo = &buffer[0];
    ULONG InSize = OutSize;
    NtStatus = QueryObj(hHandle, OBJECT_INFORMATION_CLASS(1), TypeInfo, InSize, &OutSize); //ObjectNameInformation 
    return ((POBJECT_NAME_INFORMATION)TypeInfo)->Name.Buffer; 
}

typedef NTSTATUS(NTAPI* NtDeviceIoControlFile_t) (HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
NtDeviceIoControlFile_t _NtDeviceIoControlFile = (NtDeviceIoControlFile_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDeviceIoControlFile");
NTSTATUS __stdcall hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG dwIoControlCode, PVOID lpInBuffer, ULONG InputBufferLength, PVOID lpOutBuffer, ULONG OutputBufferLength)
{ 
    if (std::find(handleslist.begin(), handleslist.end(), FileHandle) != handleslist.end()) 
    { 
        printfdbg("NtDeviceIoControlFile H:%x %ls ControlCode %x Output %x\n", FileHandle, GetHandleTypeName(FileHandle), dwIoControlCode, lpOutBuffer);
         
        auto bRet = _NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, dwIoControlCode, lpInBuffer, InputBufferLength, lpOutBuffer, OutputBufferLength);
          
        if (dwIoControlCode == SMART_GET_VERSION)  //0x074080
        {
            GETVERSIONINPARAMS* gvip = (GETVERSIONINPARAMS*)lpOutBuffer;
            printfdbg("SMART_GET_VERSION Version %d.%d Caps 0x%x DevMap 0x%02x\n",
                gvip->bVersion, gvip->bRevision, (unsigned)gvip->fCapabilities, gvip->bIDEDeviceMap); 
            //return false;
        } 
        
        if (dwIoControlCode == IOCTL_ATA_PASS_THROUGH)  //0x4D02C  ATA_PASS_THROUGH_EX 
        {
            char* pSerialNum = (char*)((DWORD)lpOutBuffer + 0x40);
            printfdbg("IOCTL_ATA_PASS_THROUGH Serial %s\n", pSerialNum);
            Fill(pSerialNum);
        }

        if (dwIoControlCode == IOCTL_SCSI_MINIPORT)  //0x4d008
        {
            auto miniport_query = reinterpret_cast<SRB_IO_CONTROL*>(lpOutBuffer);

            if (miniport_query->ControlCode == 0x1B0501) //IOCTL_SCSI_MINIPORT_IDENTIFY
            {
                const auto params = reinterpret_cast<SENDCMDOUTPARAMS*>(reinterpret_cast<uint64_t>(lpOutBuffer) + static_cast<uint64_t>(sizeof(SRB_IO_CONTROL)));
                const auto info = reinterpret_cast<IDINFO*>(params->bBuffer);
                const auto serial_number = reinterpret_cast<uint8_t*>(info->sSerialNumber);
                const auto model_number = reinterpret_cast<uint8_t*>(info->sModelNumber);

                printfdbg("IOCTL_SCSI_MINIPORT Serial %s %s .\n", serial_number, model_number);

                Fill(info->sSerialNumber);
                Fill(info->sModelNumber);
            }
            else
                //1b0502 IOCTL_SCSI_MINIPORT_READ_SMART_ATTRIBS
                //1b0503 IOCTL_SCSI_MINIPORT_READ_SMART_THRESHOLDS
                printfdbg("IOCTL_SCSI_MINIPORT ControlCode %x\n", miniport_query->ControlCode);
        }

        if (dwIoControlCode == IOCTL_DISK_GET_DRIVE_GEOMETRY)  //0x70000
        {
            DISK_GEOMETRY* pdg = (DISK_GEOMETRY*)lpOutBuffer;
            if (bRet)
            {
                ULONGLONG DiskSize = pdg->Cylinders.QuadPart * (ULONG)pdg->TracksPerCylinder *
                    (ULONG)pdg->SectorsPerTrack * (ULONG)pdg->BytesPerSector;
                printf("IOCTL_DISK_GET_DRIVE_GEOMETRY Cylinders %I64d Ds %I64u MediaType %hhx\n",
                    pdg->Cylinders, DiskSize, pdg->MediaType);
            }
        }

        if (dwIoControlCode == SMART_RCV_DRIVE_DATA)  //0x07C088
        {
            SENDCMDINPARAMS* cmdIn = (SENDCMDINPARAMS*)lpInBuffer;
            SENDCMDOUTPARAMS* lpAttrHdr = (SENDCMDOUTPARAMS*)lpOutBuffer;

            printfdbg("SMART_RCV_DRIVE_DATA Serial %s\n", (char*)(lpAttrHdr->bBuffer + 20));
            Fill((char*)lpAttrHdr->bBuffer, lpAttrHdr->cBufferSize);
        }

        if (dwIoControlCode == IOCTL_STORAGE_QUERY_PROPERTY)  //0x2d1400
        {
            string op = "IOCTL_STORAGE_QUERY_PROPERTY";

            STORAGE_DEVICE_DESCRIPTOR* tpStorageDeviceDescripter = (PSTORAGE_DEVICE_DESCRIPTOR)lpOutBuffer;

            LPSTR ProductId = tpStorageDeviceDescripter->ProductIdOffset ? reinterpret_cast<PCHAR>(tpStorageDeviceDescripter) + tpStorageDeviceDescripter->ProductIdOffset : NULL;
            LPSTR VendorId = tpStorageDeviceDescripter->VendorIdOffset ? reinterpret_cast<PCHAR>(tpStorageDeviceDescripter) + tpStorageDeviceDescripter->VendorIdOffset : NULL;
            LPSTR Serial = tpStorageDeviceDescripter->SerialNumberOffset ? reinterpret_cast<PCHAR>(tpStorageDeviceDescripter) + tpStorageDeviceDescripter->SerialNumberOffset : NULL;
            LPSTR Revision = tpStorageDeviceDescripter->ProductRevisionOffset ? reinterpret_cast<PCHAR>(tpStorageDeviceDescripter) + tpStorageDeviceDescripter->ProductRevisionOffset : NULL;

            if (ProductId && !IsBadReadPtr(tpStorageDeviceDescripter + tpStorageDeviceDescripter->ProductIdOffset, 24))
            {
                op += " ProductId ";
                op += string(ProductId);
                Fill(ProductId);
            }

            if (VendorId && !IsBadReadPtr(tpStorageDeviceDescripter + tpStorageDeviceDescripter->VendorIdOffset, 24))
            {
                op += " VendorId ";
                op += string(VendorId);
                Fill(VendorId);
            }

            if (Revision && !IsBadReadPtr(tpStorageDeviceDescripter + tpStorageDeviceDescripter->ProductRevisionOffset, 24))
            {
                op += " Revision ";
                op += string(Revision);
                Fill(Revision);
            }
            if (Serial && !IsBadReadPtr(tpStorageDeviceDescripter + tpStorageDeviceDescripter->SerialNumberOffset, 24))
            {
                op += " Serial ";
                op += string(Serial);
                Fill(Serial);
            }

            printfdbg("%s\n", op.c_str());
            //((STORAGE_PROPERTY_QUERY*)OutputBuffer)->PropertyId = (STORAGE_PROPERTY_ID)0;;
        }
        
        return bRet;
    }

    return _NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, dwIoControlCode, lpInBuffer, InputBufferLength, lpOutBuffer, OutputBufferLength);
}

typedef NTSTATUS(NTAPI* ZwCreateProcessEx_t)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ParentProcess, IN ULONG Flags, IN HANDLE SectionHandle OPTIONAL, IN HANDLE DebugPort OPTIONAL, IN HANDLE ExceptionPort OPTIONAL, IN BOOLEAN InJob);
ZwCreateProcessEx_t _NtCreateProcessEx = (ZwCreateProcessEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
NTSTATUS __stdcall hkCreateProcessEx(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ParentProcess, IN ULONG Flags, IN HANDLE SectionHandle OPTIONAL, IN HANDLE DebugPort OPTIONAL, IN HANDLE ExceptionPort OPTIONAL, IN BOOLEAN InJob)
{
    printfdbg("\nCreateProcessEx called : %ls\n\n", ObjectAttributes->ObjectName->Buffer);
    return _NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob);
}

typedef NTSTATUS(NTAPI* ZwLdrInitializeThunk_t) (PCONTEXT NormalContext, DWORD Unknown2, DWORD Unknown3);
ZwLdrInitializeThunk_t _NtLdrInitializeThunk = (ZwLdrInitializeThunk_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrInitializeThunk");
NTSTATUS __stdcall hkNtLdrInitializeThunk(PCONTEXT NormalContext, DWORD Unknown2, DWORD Unknown3)
{
    //printfdbg("! hkNtLdrInitializeThunk %x %x %x -> %x (%ls)\n", NormalContext, Unknown2, Unknown3, NormalContext->Dr0, GetModuleOfAddress(NormalContext->Dr0));
    return _NtLdrInitializeThunk(NormalContext, Unknown2, Unknown3);
}

typedef NTSTATUS(NTAPI* ZwCreateFile_t)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
ZwCreateFile_t _NtCreateFile = (ZwCreateFile_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
NTSTATUS __stdcall hkCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\PhysicalDrive") || wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\Scsi"))
    {
        //return false; 
        auto ret = _NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
        if (*(DWORD*)FileHandle) {
            handleslist.push_back((HANDLE)(*(DWORD*)FileHandle));
            printfdbg("NtCreateFile %ls -> %x\n", ObjectAttributes->ObjectName->Buffer, *(DWORD*)FileHandle);
        }
        return ret;
    }

    return _NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

typedef NTSTATUS(NTAPI* NtClose_t) (HANDLE Handle);
NtClose_t _NtClose = (NtClose_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
NTSTATUS __stdcall hkNtClose(HANDLE Handle)
{
    if (auto pos = std::find(handleslist.begin(), handleslist.end(), Handle) != handleslist.end()) {
        //printfdbg("Handle closed -> %x\n", Handle);  
        handleslist.erase(std::remove(handleslist.begin(), handleslist.end(), Handle), handleslist.end()); 
    }
    return _NtClose(Handle);
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
    printfdbg("NtDeviceIoControlFile %x\n", _NtDeviceIoControlFile);
    printfdbg("NtLdrUnloadDll %x\n", NtLdrUnloadDll);
    printfdbg("NtLdrInitializeThunk %x\n", _NtLdrInitializeThunk);
    printfdbg("NtCreateFile %x\n", _NtCreateFile);
    printfdbg("NtClose %x\n", _NtClose);

    printfdbg("=========================\n");

    vector<int> sig = { 0xB8,0x07,0x00,0x1B,0x00,0xE9 };
    DWORD Entry = GetAddressFromSignature(sig, 0x0, 0x10000000);
    printfdbg("removeIoHook %x\n", Entry);
    if (Entry) {
        *(DWORD*)(Entry + 0x6) -= 0x5;
    };

    NtLdrLoadDll = (pLdrLoadDll)DetourFunction((PBYTE)NtLdrLoadDll, (PBYTE)hkLdrLoadDll);
    _NtCreateThreadEx = (ZwCreateThreadEx_t)DetourFunction((PBYTE)_NtCreateThreadEx, (PBYTE)hkCreateThreadEx);
    NtLdrUnloadDll = (pLdrUnloadDll)DetourFunction((PBYTE)NtLdrUnloadDll, (PBYTE)hkLdrUnloadDll);

    if (hwidspoof) { 
        _NtDeviceIoControlFile = (NtDeviceIoControlFile_t)DetourFunction((PBYTE)_NtDeviceIoControlFile, (PBYTE)hkNtDeviceIoControlFile);
        _NtCreateFile = (ZwCreateFile_t)DetourFunction((PBYTE)_NtCreateFile, (PBYTE)hkCreateFile);
        _NtClose = (NtClose_t)DetourFunction((PBYTE)_NtClose, (PBYTE)hkNtClose);
        //_NtLdrInitializeThunk = (ZwLdrInitializeThunk_t)DetourFunction((PBYTE)_NtLdrInitializeThunk, (PBYTE)hkNtLdrInitializeThunk);
    }

    //printfdbg("SetWindowDisplayAffinity %d\n",SetWindowDisplayAffinity(GetForegroundWindow(), WDA_EXCLUDEFROMCAPTURE));

    while (1) {
        Sleep(10);
        if (GetAsyncKeyState(VK_END))  break;
    }

#ifdef CONSOLE
    fclose(fp);
    FreeConsole();
#endif

    Beep(600, 400);

    DetourRemove(reinterpret_cast<BYTE*>(NtLdrLoadDll), reinterpret_cast<BYTE*>(hkLdrLoadDll));
    DetourRemove(reinterpret_cast<BYTE*>(_NtCreateThreadEx), reinterpret_cast<BYTE*>(hkCreateThreadEx));
    DetourRemove(reinterpret_cast<BYTE*>(NtLdrUnloadDll), reinterpret_cast<BYTE*>(hkLdrUnloadDll));

    if (hwidspoof) { 
        DetourRemove(reinterpret_cast<BYTE*>(_NtDeviceIoControlFile), reinterpret_cast<BYTE*>(hkNtDeviceIoControlFile));
        DetourRemove(reinterpret_cast<BYTE*>(_NtCreateFile), reinterpret_cast<BYTE*>(hkCreateFile));
        DetourRemove(reinterpret_cast<BYTE*>(_NtClose), reinterpret_cast<BYTE*>(hkNtClose));
    }

    Sleep(100);
    FreeLibraryAndExitThread(myhModule, 0);

    return 0;
}

extern "C" __declspec(dllexport) int InitFn(pass_args * argumento)
{
    havemodule = argumento->havemodule;
    hwidspoof = argumento->hwidspoof;

    if (havemodule)
    {
        memcpy(modules, argumento->modules, MAX_PATH);
        if (wcsstr(modules, L"everymodule"))
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


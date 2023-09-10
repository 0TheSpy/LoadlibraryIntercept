#include "stuff.h" 

int FindProcByName(wchar_t* processname) {
	HANDLE hSnapshot;
	PROCESSENTRY32W pe;
	int pid = 0;
	BOOL hResult;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

	pe.dwSize = sizeof(PROCESSENTRY32W);
	hResult = Process32FirstW(hSnapshot, &pe);

	while (hResult) {
		if (wcsstr(processname, pe.szExeFile)) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32NextW(hSnapshot, &pe);
	}

	CloseHandle(hSnapshot);
	return pid;
}

uintptr_t GetModuleBaseEx(DWORD procId, const char* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_stricmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

uintptr_t GetProcAddressEx(HANDLE hProcess, uintptr_t moduleBase, const char* function)
{
	if (!function || !hProcess || !moduleBase)
		return 0;

	IMAGE_DOS_HEADER Image_Dos_Header = { 0 };

	if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase), &Image_Dos_Header, sizeof(IMAGE_DOS_HEADER), nullptr))
		return 0;

	if (Image_Dos_Header.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	IMAGE_NT_HEADERS Image_Nt_Headers = { 0 };

	if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase + Image_Dos_Header.e_lfanew), &Image_Nt_Headers, sizeof(IMAGE_NT_HEADERS), nullptr))
		return 0;

	if (Image_Nt_Headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	IMAGE_EXPORT_DIRECTORY Image_Export_Directory = { 0 };
	uintptr_t img_exp_dir_rva = 0;

	if (!(img_exp_dir_rva = Image_Nt_Headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
		return 0;

	if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase + img_exp_dir_rva), &Image_Export_Directory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
		return 0;

	uintptr_t EAT = moduleBase + Image_Export_Directory.AddressOfFunctions;
	uintptr_t ENT = moduleBase + Image_Export_Directory.AddressOfNames;
	uintptr_t EOT = moduleBase + Image_Export_Directory.AddressOfNameOrdinals;

	WORD ordinal = 0;
	SIZE_T len_buf = strlen(function) + 1;
	char* temp_buf = new char[len_buf];

	for (size_t i = 0; i < Image_Export_Directory.NumberOfNames; i++)
	{
		uintptr_t tempRvaString = 0;

		if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(ENT + (i * sizeof(uintptr_t))), &tempRvaString, sizeof(uintptr_t), nullptr))
			return 0;

		if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase + tempRvaString), temp_buf, len_buf, nullptr))
			return 0;

		if (!lstrcmpi(function, temp_buf))
		{
			if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(EOT + (i * sizeof(WORD))), &ordinal, sizeof(WORD), nullptr))
				return 0;

			uintptr_t temp_rva_func = 0;

			if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(EAT + (ordinal * sizeof(uintptr_t))), &temp_rva_func, sizeof(uintptr_t), nullptr))
				return 0;

			delete[] temp_buf;
			return moduleBase + temp_rva_func;
		}
	}
	delete[] temp_buf;
	return 0;
}



DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase
		+ ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
	while (relocation->VirtualAddress) {
		PWORD relocationInfo = (PWORD)(relocation + 1);
		for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
			if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				*(PDWORD)(loaderData->imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;

		relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase
		+ ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (importDirectory->Characteristics) {
		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);

		HMODULE module = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDirectory->Name);

		if (!module)
			return FALSE;

		while (originalFirstThunk->u1.AddressOfData) {
			DWORD Function = (DWORD)loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->imageBase + originalFirstThunk->u1.AddressOfData))->Name);

			if (!Function)
				return FALSE;

			firstThunk->u1.Function = Function;
			originalFirstThunk++;
			firstThunk++;
		}
		importDirectory++;
	}

	if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
		DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
			(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
			((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);

		return result;
	}
	return TRUE;
}

void stub() {};

#define NT_SUCCESS(x) ((x) >= 0)
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

int rvm(HANDLE hProcess, PVOID addr, int num, void* buf)
{
	SIZE_T sz = 0;
	DWORD oldProtect = 0;
	VirtualProtectEx(hProcess, addr, num, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (NTSTATUS status = NtReadVirtualMemory(hProcess, addr, buf, num, &sz) >= 0)
	{
		VirtualProtectEx(hProcess, addr, num, oldProtect, NULL);
#ifdef DEBUG
		//cout << "NtReadVirtualMemory failed with status: " << hex << status << "\n";
		//printf("RVM error %02X at %08x\n", status, addr);
#endif 
		return 0;
	}

	VirtualProtectEx(hProcess, addr, num, oldProtect, NULL);
	return sz;
}


BOOL ComparePattern(HANDLE pHandle, DWORD address, char* pattern, char* mask) {
	DWORD patternSize = strlen(mask);
	auto memBuf = new char[patternSize + 1];
	memset(memBuf, 0, patternSize + 1);
	rvm(pHandle, (PVOID)address, patternSize, memBuf);
	for (DWORD i = 1; i < patternSize; i++) {
		if (memBuf[i] != pattern[i] && mask[i] != *"?") {
			delete memBuf;
			return false;
		}
	}
	delete memBuf;
	return true;
}

DWORD ExternalAoBScan(HANDLE pHandle, DWORD moduleBase, char* pattern, char* mask) {

	DWORD patternSize = strlen(mask);
	DWORD moduleSize = 0x30000000;

	auto moduleBytes = new char[moduleSize + 1];
	memset(moduleBytes, 0, moduleSize + 1);
	rvm(pHandle, (PVOID)moduleBase, moduleSize, moduleBytes);
	for (int i = 0; i + patternSize < moduleSize; i++) {
		if (pattern[0] == moduleBytes[i]) {
			if (ComparePattern(pHandle, moduleBase + i, pattern, mask)) {
				delete moduleBytes;
				printfdbg("Found pattern at %x\n", moduleBase + i);
				return moduleBase + i;
			}
		}
	}
	delete moduleBytes;
	printfdbg("pattern not found!\n");
	return NULL;
}


DWORD MyLoadLibrary(HANDLE hProcess, char* dx_binary)
{
	PIMAGE_NT_HEADERS dx_ntHeaders = (PIMAGE_NT_HEADERS)((char*)dx_binary + ((PIMAGE_DOS_HEADER)dx_binary)->e_lfanew);

	PBYTE dx_executableImage = (PBYTE)VirtualAllocEx(hProcess, NULL, dx_ntHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess, dx_executableImage, dx_binary,
		dx_ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER dx_sectionHeaders = (PIMAGE_SECTION_HEADER)(dx_ntHeaders + 1);
	for (int i = 0; i < dx_ntHeaders->FileHeader.NumberOfSections; i++)
		WriteProcessMemory(hProcess, dx_executableImage + dx_sectionHeaders[i].VirtualAddress,
			(char*)dx_binary + dx_sectionHeaders[i].PointerToRawData, dx_sectionHeaders[i].SizeOfRawData, NULL);

	LoaderData* dx_loaderMemory = (LoaderData*)VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READ);

	LoaderData dx_loaderParams;
	dx_loaderParams.imageBase = dx_executableImage;
	dx_loaderParams.loadLibraryA = LoadLibraryA;
	dx_loaderParams.getProcAddress = GetProcAddress;

	WriteProcessMemory(hProcess, dx_loaderMemory, &dx_loaderParams, sizeof(LoaderData),
		NULL);
	WriteProcessMemory(hProcess, dx_loaderMemory + 1, loadLibrary,
		(DWORD)stub - (DWORD)loadLibrary, NULL);
	WaitForSingleObject(CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(dx_loaderMemory + 1),
		dx_loaderMemory, 0, NULL), INFINITE);
	VirtualFreeEx(hProcess, dx_loaderMemory, 0, MEM_RELEASE);

	printfdbg("Dll allocated at %x\n", (DWORD)dx_executableImage);
	return (DWORD)dx_executableImage;
}

bool NopMemory(HANDLE hProcess, DWORD addr, size_t size)
{
	DWORD this_oldProtect = 0;
	if (!VirtualProtectEx(hProcess, (PVOID)addr, size, PAGE_EXECUTE_READWRITE, &this_oldProtect))
		return 0;

	BYTE* nop_array = new BYTE[size];
	memset(nop_array, 0x90, size);
	WriteProcessMemory(hProcess, (PVOID)addr, nop_array, size, 0);

	VirtualProtectEx(hProcess, (PVOID)addr, size, this_oldProtect, &this_oldProtect);
	delete[] nop_array;

	return 1;
}


char* GetLastErrorAsText()
{
	DWORD errorMessageID = ::GetLastError();
	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
	std::ostringstream out;
	out << errorMessageID << " (0x" << hex << errorMessageID << "): " << messageBuffer;
	return (char*)(out.str().c_str());
}

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES oldtp;    // old token privileges 
	TOKEN_PRIVILEGES tp;
	DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printfdbg("LookupPrivilegeValue error: %s\n", GetLastErrorAsText());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)&oldtp,
		(PDWORD)&dwSize))
	{
		printfdbg("AdjustTokenPrivileges error: %s\n", GetLastErrorAsText()); //Get error 6 here (ie invalid handle)
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) 
	{
		printfdbg("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

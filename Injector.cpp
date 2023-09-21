#include <iostream> 
#include <Windows.h>
  
struct pass_args    
{ 
	bool havemodule = false;   
	bool hwidspoof = false;
	bool regmon = false;
	wchar_t modules[MAX_PATH];       
};        
pass_args inject_args;         
      
#include "stuff.h"  
 
bool Inject(wchar_t procname[MAX_PATH], bool existing)
{   
	HANDLE hToken; 
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	SetPrivilege(hToken, "SeBackupPrivilege", 1);
	SetPrivilege(hToken, "SeDebugPrivilege", 1);
	CloseHandle(hToken);
	 
	HANDLE hProcess = 0;
	PROCESS_INFORMATION PI; 

	if (!existing) {
		memset(&PI, 0, sizeof(PROCESS_INFORMATION));
		STARTUPINFOEXW SI;
		memset(&SI, 0, sizeof(STARTUPINFOEXW));
		SIZE_T attributeSize;
		InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
		SI.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
		InitializeProcThreadAttributeList(SI.lpAttributeList, 1, 0, &attributeSize);
		DWORD PID = FindProcByName((wchar_t*)(L"svchost.exe"));
		printfdbg("FindProcByName %d\n", PID);
		HANDLE parentProcessHandle = OpenProcess(
			PROCESS_ALL_ACCESS, //MAXIMUM_ALLOWED
			false,
			PID);
		if (parentProcessHandle) {
			printfdbg(("Open parent process OK: %d\n"), parentProcessHandle);

			UpdateProcThreadAttribute(
				SI.lpAttributeList,
				0,
				PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
				&parentProcessHandle,
				sizeof(HANDLE),
				NULL,
				NULL);

		}
		else
			printfdbg(("Open parent process error %s\n"), GetLastErrorAsText());

		SI.StartupInfo.cb = sizeof(STARTUPINFOEXW);

		if (!CreateProcessW(NULL, procname, NULL, NULL, NULL,
			EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &SI.StartupInfo, &PI))
			printfdbg("CreateProcessW error %s\n", GetLastErrorAsText());

		hProcess = PI.hProcess;
	}

	else {
		DWORD procID = 0;
		do {
			procID = FindProcByName(procname);

			if (!procID) {
				printfdbg("process %ls not found\n", procname);
				Sleep(1);
			} 
		} while (!procID);

		printfdbg("Proccess ID %x\n", procID);

		if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID))) 
			printfdbg("OpenProcess %x %s\n", hProcess, GetLastErrorAsText());  
	} 
	  
	if (!hProcess)
		return 0; 

	HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL1), "DLL");
	HANDLE hRes = LoadResource(NULL, hResInfo);
	LPVOID binary = LockResource(hRes);

	DWORD dllptr = MyLoadLibrary(hProcess, (char*)binary);
	if (!dllptr)
		return false;
	 
	LPVOID param = VirtualAllocEx(hProcess, NULL, sizeof(pass_args), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, param, &inject_args, sizeof(pass_args), 0);
	 
	HANDLE hLoadThread_setfpshotkey = CreateRemoteThread(hProcess, 0, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddressEx(hProcess, dllptr, "InitFn"),
		param, 0, 0);

	if (!existing) {
		Sleep(1000);

		if (ResumeThread(PI.hThread))
		{
			CloseHandle(PI.hProcess);
			CloseHandle(PI.hThread);
			return 0;
		}
		else printfdbg(("Error resuming thread\r\n"));
	}

	return 1;
}
    
int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPWSTR lpCmdLine, int nCmdShow)
{ 
#ifdef CONSOLE
	AllocConsole();
	FILE* fp;
	freopen_s(&fp, "CONOUT$", "w", stdout); 
	printfdbg("console alloc\n"); 
#endif 
	 
	wchar_t procname[MAX_PATH] = L""; bool hprocname = false;
	wchar_t* modules = 0;
	bool existing = false; 
	 
	printfdbg("lpCmdLine %ls\n", lpCmdLine);

	LPWSTR* szArglist;
	int nArgs = 0; 
	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs); 
	for (int i = 0; i < nArgs; i++) {  
		if (wcsstr(szArglist[i], L"-t") || wcsstr(szArglist[i], L"-target")) {
			if (i + 1 < nArgs) {
				i++; 
				memcpy(procname, szArglist[i], MAX_PATH); 
				hprocname = true;
				printf("Target process name %ls\n", procname);
			} 
			else {
				printfdbg("-target option requires one argument.");
				system("pause");
				return 0;
			}
		} 
		
		if (wcsstr(szArglist[i], L"-m") || wcsstr(szArglist[i], L"-module")) {
			if (i + 1 < nArgs) {
				i++;
				modules = szArglist[i];
				printf("Library module name %ls\n", modules);
				inject_args.havemodule = true;
				memcpy(inject_args.modules, modules, MAX_PATH);
			}
			else {
				printfdbg("-module option requires one argument.\n");
				system("pause"); 
				return 0;
			}
		}

		if (wcsstr(szArglist[i], L"-e") || wcsstr(szArglist[i], L"-existing")) {
			printf("Loading to existing process\n");
			existing = true;
		}

		if (wcsstr(szArglist[i], L"-hwid")) {
			printf("Spoofing HWID\n");
			inject_args.hwidspoof = true;
		}

		if (wcsstr(szArglist[i], L"-regmon")) {
			printf("Registry Monitoring\n");
			inject_args.regmon = true;
		}

	} 
	if (!hprocname)
	{ 
		printfdbg("Target process not found!\n");
		system("pause");
		return 0;
	}

	LocalFree(szArglist);
	 
	Inject(procname, existing);

#ifdef CONSOLE
	system("pause");
#endif
	return 0;
}
 

 


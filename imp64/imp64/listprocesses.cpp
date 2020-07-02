#include "stdafx.h"

DWORD   ProcessIDs[4096];			//maximum number of processes...
HMODULE hModule[4096];
char	moduleName[MAX_PATH];

void ListProcesses()
{
	char buffer[1024];

	DWORD pReturned;
	DWORD numProcesses;
	DWORD i;
	HANDLE phandle;

	::EnumProcesses(ProcessIDs, 4096 * sizeof(DWORD), &pReturned);
	numProcesses = pReturned / sizeof(DWORD);
	i = numProcesses - 1;
	//for (i = 0; i < numProcesses; i++){
	while (i != 0xFFFFFFFF){
		phandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessIDs[i]);
		if (phandle){
			if (::EnumProcessModules(phandle, hModule, 4096 * sizeof(HMODULE), &pReturned)){
				if (::GetModuleFileNameExA(phandle, hModule[0], moduleName, MAX_PATH)){
					::sprintf_s((char *)&buffer, 1024, "%.08X - %s", ProcessIDs[i], moduleName);
					InsertIntoCombox((LPSTR)&buffer);
				}else{
					::sprintf_s((char *)&buffer, 1024, "%.08X - can't retrive process name", ProcessIDs[i]);
					InsertIntoCombox((LPSTR)&buffer);
				}

			}
			::CloseHandle(phandle);
		}

		i--;
	}

}
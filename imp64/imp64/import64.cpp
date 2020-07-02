#include "stdafx.h"

DWORD CalculateImportSize(PIMPORT_STRUCT pi, DWORD *p_numIIDs){
	PIMPORT_STRUCT pImport = pi;
	DWORD totalsize = 0;
	DWORD numIIDs = 0;
	PULONG_PTR ordinal;

	while (pImport->is_address){
		totalsize+= sizeof(IMAGE_IMPORT_DESCRIPTOR);
		totalsize+= pImport->is_dlllen;
		totalsize+= pImport->is_apilen;
		totalsize+= 18;			//one for original first thunk, one for terminating 0 and 2 for HINT...!!!

		numIIDs++;
		pImport++;
	}
	totalsize+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
	*p_numIIDs = numIIDs + 1;	//for NULL terminating IMAGE_IMPORT_DESCRIPTOR!!!
	return totalsize;
}

PVOID BuildImportTable(DWORD section_rva, PIMPORT_STRUCT pi, DWORD iat_size, DWORD numIIDs){
	PVOID new_iat;
	PIMAGE_IMPORT_DESCRIPTOR c_import;
	PIMPORT_STRUCT pImport;
	PUCHAR current;

	pImport = pi;
	new_iat = ::VirtualAlloc(0, iat_size, MEM_COMMIT, PAGE_READWRITE);
	c_import = (PIMAGE_IMPORT_DESCRIPTOR)new_iat;
	current = ((PUCHAR)c_import + numIIDs * sizeof(IMAGE_IMPORT_DESCRIPTOR));

	while (pImport->is_address){
		::memcpy(current, &pImport->is_dllname, pImport->is_dlllen);
		c_import->Name = (section_rva + current - (PUCHAR)new_iat);
		c_import->FirstThunk = pImport->is_address;
		current += pImport->is_dlllen;

		c_import->OriginalFirstThunk = current - (PUCHAR)new_iat + section_rva;
		if (*(PULONG_PTR)&pImport->is_apiname & 0x8000000000000000){
			*(PULONG_PTR)current = *(PULONG_PTR)&pImport->is_apiname;
			current+=16;
		}else{
			*(PULONG_PTR)current = current - (PUCHAR)new_iat + section_rva + 16;
			current+=18;
			::memcpy(current, &pImport->is_apiname, pImport->is_apilen);
			current+= pImport->is_apilen;
		}
		pImport++;
		c_import++;

	}

	return new_iat;
}

VOID AdjustFirstThunk(LPSTR dumpFileName){
	HANDLE fhandle, shandle;
	PVOID  mhandle;
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_IMPORT_DESCRIPTOR c_import;

	ULONG_PTR remapped;
	PULONG_PTR adjust_me, adjust_with;

	fhandle = ::CreateFileA(dumpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
	shandle = ::CreateFileMappingA(fhandle, 0, PAGE_READWRITE, 0,0,0);
	mhandle = ::MapViewOfFile(shandle, FILE_MAP_ALL_ACCESS, 0,0,0);

	mz = (PIMAGE_DOS_HEADER)mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)mhandle + mz->e_lfanew);
	section = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->FileHeader.SizeOfOptionalHeader);

	remapped = (ULONG_PTR)::VirtualAlloc(0, pe64->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	
	for (ULONG i = 0; i < pe64->FileHeader.NumberOfSections; i++)
		::memcpy((PVOID)(remapped + section[i].VirtualAddress), (PVOID)((ULONG_PTR)mhandle + section[i].PointerToRawData), section[i].SizeOfRawData);

	c_import = (PIMAGE_IMPORT_DESCRIPTOR)(remapped + pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (c_import->Name){
		adjust_with = (PULONG_PTR)(c_import->OriginalFirstThunk + remapped);
		adjust_me = (PULONG_PTR)(c_import->FirstThunk + remapped);
		*adjust_me = 0xdeadc0dedeadc0de; //*adjust_with;
		c_import++;
	}
	for (ULONG i = 0; i < pe64->FileHeader.NumberOfSections; i++)
		::memcpy((PVOID)((ULONG_PTR)mhandle + section[i].PointerToRawData), (PVOID)(remapped + section[i].VirtualAddress), section[i].SizeOfRawData);

	::VirtualFree((PVOID)remapped, 0, MEM_DECOMMIT);
	::UnmapViewOfFile(mhandle);
	::CloseHandle(shandle);
	::CloseHandle(fhandle);



}

void HandleForwards(PIMPORT_STRUCT pi, HANDLE phandle){
	PIMPORT_STRUCT pImport;

	pImport = pi;

	while(pImport->is_address){
		if (!::strnicmp((char *)&pImport->is_dllname, "ntdll.dll", pImport->is_dlllen))
			CycleNameByDllName("kernel32.dll", "ntdll", pImport, phandle);
		pImport++;
	}

}

void CycleNameByDllName(LPSTR f_dllName, LPSTR o_dllName, PIMPORT_STRUCT pImport, HANDLE phandle){
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_EXPORT_DIRECTORY c_export;
	ULONG_PTR  e_start, e_size;
	ULONG_PTR  apiAddress;

	DWORD * addressOfNames;
	DWORD * addressOfFunctions;
	WORD  * pOrdinals;

	DWORD   dllNameLen = strlen(o_dllName);
	
	DWORD cbNeeded;
	HMODULE *hModule;
	DWORD num_of_modules;
	PVOID  modBase = NULL;
	DWORD  nameLen;
	MODULEINFO moduleInfo;
	char   mod_name[MAX_PATH];

	hModule = (HMODULE *)GlobalAlloc(GPTR, 1024 * sizeof(HMODULE));
	//instead of loadlibrarya we read module from remote process!!!!
	::EnumProcessModules(phandle, hModule, 1024* sizeof(HMODULE), &cbNeeded);

	num_of_modules = cbNeeded / sizeof(HMODULE);

	for (DWORD i = 0; i < num_of_modules; i++){
		::memset(&mod_name, 0, MAX_PATH);
		nameLen = ::GetModuleBaseNameA(phandle, hModule[i], (LPSTR)&mod_name, MAX_PATH);
		if (nameLen)
			if (!::strnicmp((char *)&mod_name, f_dllName, nameLen)){
				::GetModuleInformation(phandle, hModule[i], &moduleInfo, sizeof(MODULEINFO));	

				modBase = ::VirtualAlloc(0, moduleInfo.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
				::ReadProcessMemory(phandle, moduleInfo.lpBaseOfDll, modBase, moduleInfo.SizeOfImage, 0);
				break;
			}
	}

	//ULONG_PTR dllBase = (ULONG_PTR)::LoadLibraryA(f_dllName);
	ULONG_PTR dllBase = (ULONG_PTR)modBase;

	if (!modBase){
		GlobalFree(hModule);
		return;
	}

	mz       = (PIMAGE_DOS_HEADER)dllBase;
	pe64     = (PIMAGE_NT_HEADERS64)(dllBase + mz->e_lfanew);
	c_export = (PIMAGE_EXPORT_DIRECTORY)pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!c_export) return;
	c_export = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)c_export+dllBase);

	e_start = pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + dllBase;
	e_size  = pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size + e_start;

	addressOfNames     = (DWORD *)(dllBase + c_export->AddressOfNames);
	addressOfFunctions = (DWORD *)(dllBase + c_export->AddressOfFunctions);
	pOrdinals          = (WORD  *)(dllBase + c_export->AddressOfNameOrdinals);

	for (ULONG i = 0; i < c_export->NumberOfNames; i++){
		apiAddress = addressOfFunctions[pOrdinals[i]] + dllBase;
		if (apiAddress >= e_start && apiAddress < e_size){
			if (!::strnicmp((char *)apiAddress, o_dllName, dllNameLen)){
				apiAddress += dllNameLen;
				apiAddress ++;

				if (!::strnicmp((char *)apiAddress, (char *)&pImport->is_apiname, pImport->is_apilen)){
					//we have found our stuff...
					::memset(&pImport->is_apiname, 0, 256);
					::memset(&pImport->is_dllname, 0, 256);

					apiAddress = addressOfNames[i] + dllBase;
					::strcpy((char *)&pImport->is_apiname, (char *)apiAddress);
					::strcpy((char *)&pImport->is_dllname, f_dllName);
					pImport->is_apilen = ::strlen((char *)&pImport->is_apiname) + 1;
					pImport->is_dlllen = ::strlen((char *)&pImport->is_dllname) + 1;
					break;
				}


			}

		}


	}


	::VirtualFree(modBase, 0, MEM_DECOMMIT);
	::GlobalFree(hModule);


}
#include "stdafx.h"

ULONG_PTR s_start;
DWORD     s_size;
DWORD	  sizeOfImage;
ULONG_PTR imagebase;

extern HMODULE hModule[4096];
extern PIMPORT_STRUCT g_pImport;

bool AnalyzeImports(DWORD pid, LPSTR originalFileName){
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_SECTION_HEADER section;

	HANDLE fhandle, shandle, d_fhandle, d_shandle;
	PVOID mhandle, d_mhandle;
	HANDLE phandle;
	PVOID code_section;
	PUCHAR current;
	DWORD  c_size;
	PIMPORT_STRUCT pImport, pImport_temp;
	ULONG_PTR apiAddress;
	__int64 apiOffset;
	ULONG_PTR rip;
	DWORD numIIDs, iat_size;
	DWORD dummy;
	MODULEINFO modinfo;

	__try{
	phandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!phandle){
		return false;
	}
	::EnumProcessModules(phandle, hModule, 4096 * sizeof(HMODULE), &dummy);
	::GetModuleInformation(phandle, hModule[0], &modinfo, sizeof(MODULEINFO));
	imagebase = (ULONG_PTR)modinfo.lpBaseOfDll;

	fhandle = ::CreateFileA(originalFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
	if (fhandle == INVALID_HANDLE_VALUE){
		return false;
	}
	shandle = ::CreateFileMappingA(fhandle, 0, PAGE_READONLY, 0,0,0);
	mhandle = ::MapViewOfFile(shandle, FILE_MAP_READ, 0,0,0);
	
	mz = (PIMAGE_DOS_HEADER)mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)mhandle + mz->e_lfanew);
	section = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->FileHeader.SizeOfOptionalHeader);

	c_size = section[0].VirtualAddress + section[0].Misc.VirtualSize;
	pImport = (PIMPORT_STRUCT)::VirtualAlloc(0, 0x10000000, MEM_COMMIT, PAGE_READWRITE);
	pImport_temp = pImport;

	code_section = GlobalAlloc(GPTR, c_size);

	::ReadProcessMemory(phandle, (PVOID)(imagebase + section[0].VirtualAddress), code_section, c_size, 0);

	current = (PUCHAR)code_section;

	while(current < ((PUCHAR)code_section + c_size - 10))
	{
		/*
		2.2.1.6 RIP-Relative Addressing
			A new addressing form, RIP-relative (relative instruction-pointer) addressing, is
			implemented in 64-bit mode. An effective address is formed by adding displacement
			to the 64-bit RIP of the next instruction.
		*/
		if (*(PWORD)current == 0x15FF ||		//call qword ptr[rip+delta]
			*(PWORD)current == 0x25FF ||		//jmp  qword ptr[rip+delta]
			*(PWORD)current == 0x35FF    		//push qword ptr[rip+delta]
			){
			apiOffset = *(int *)&current[2];
			rip = current - (PUCHAR)code_section;
			rip += section[0].VirtualAddress + imagebase;
			rip+= 6; //size of instruction
			apiOffset += rip;
			if (::ReadProcessMemory(phandle, (PVOID)apiOffset, &apiAddress, sizeof(ULONG_PTR), 0)){
				if (!IsResolved(pImport, apiOffset - imagebase)){
					if (ResolveApi64(pid, apiAddress, pImport_temp)){
						pImport_temp->is_address = apiOffset - imagebase;
						//printf("API at %.16X %s!%s\n", apiOffset, &pImport_temp->is_dllname, &pImport_temp->is_apiname);
						current += 6;
						pImport_temp++;
						continue;
					}
				}
			}
		}else{
			//all possible variants of mov from mov rax-r15
			if ((current[0] == 0x48 || current[0] == 0x4C) && (current[1] == 0x8B || current[1] == 0x8D)){
				if (current[2] == 0x05 ||
					current[2] == 0x0D ||
					current[2] == 0x15 ||
					current[2] == 0x1D ||
					current[2] == 0x25 ||
					current[2] == 0x2D ||
					current[2] == 0x35 ||
					current[2] == 0x3D){

						apiOffset = *(int *)&current[3];
						rip = current - (PUCHAR)code_section;
						rip += section[0].VirtualAddress + imagebase;
						rip+=7;
						apiOffset += rip;
						if (::ReadProcessMemory(phandle, (PVOID)apiOffset, &apiAddress, sizeof(ULONG_PTR), 0)){
							if (!IsResolved(pImport, apiOffset - imagebase)){
								if (ResolveApi64(pid, apiAddress, pImport_temp)){
									//printf("API at %.16X %s!%s\n", apiOffset, &pImport_temp->is_dllname, &pImport_temp->is_apiname);
									pImport_temp->is_address = apiOffset - imagebase;
									current+=7;
									pImport_temp++;
									continue;
								}
							}
						}
				}

			}
		


		}


		current++;
	}
	//no  apis were found...
	::GlobalFree(code_section);
	g_pImport = pImport;
	if (!pImport->is_address) return false;

	::UnmapViewOfFile(mhandle);
	::CloseHandle(shandle);
	::CloseHandle(fhandle);
	
	HandleForwards(pImport, phandle);
	SortByAddress(pImport);
	InsertImportsIntoList(pImport);
	CloseHandle(phandle);
	}__except(EXCEPTION_EXECUTE_HANDLER){
		return false;
	}
	return true;
}
//apply bubble sort...
void SortByAddress(PIMPORT_STRUCT pImport){
	PIMPORT_STRUCT pImport_temp = pImport;
	int array_size = 0;
	IMPORT_STRUCT i1, i2;

	while (pImport_temp->is_address){
		array_size++;
		pImport_temp++;
	}
	pImport_temp = pImport;

	for (int i = array_size - 1; i > 0; i--){
		for (int j = 0; j < i; j++){
			if (pImport_temp[j].is_address > pImport_temp[j+1].is_address){
				::memcpy(&i1, &pImport[j], sizeof(IMPORT_STRUCT));
				::memcpy(&i2, &pImport[j+1], sizeof(IMPORT_STRUCT));

				::memcpy(&pImport[j+1], &i1, sizeof(IMPORT_STRUCT));
				::memcpy(&pImport[j], &i2, sizeof(IMPORT_STRUCT));
			}
		}
	}



}

BOOL IsResolved(PIMPORT_STRUCT pImport_c, DWORD rva){
	PIMPORT_STRUCT pImport = pImport_c;

	while (pImport->is_address){
		if (pImport->is_address == rva) return TRUE;
		pImport++;


	}


	return FALSE;

}





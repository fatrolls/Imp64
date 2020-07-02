#include "stdafx.h"


DWORD GetEntryPoint(LPSTR fileName)
{
	HANDLE fhandle, shandle;
	PVOID mhandle;
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	DWORD entrypoint;

	fhandle = ::CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
	shandle = ::CreateFileMappingA(fhandle, 0, PAGE_READONLY, 0,0,0);
	mhandle = ::MapViewOfFile(shandle, FILE_MAP_READ, 0,0,0);

	mz = (PIMAGE_DOS_HEADER)mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)mhandle + mz->e_lfanew);
	
	entrypoint = pe64->OptionalHeader.AddressOfEntryPoint;

	::UnmapViewOfFile(mhandle);
	::CloseHandle(shandle);
	::CloseHandle(fhandle);
	return entrypoint;
}

VOID AddSection(LPSTR fileName, DWORD sec_size, LPSTR sec_name){
	HANDLE fhandle, shandle;
	PVOID mhandle;
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_SECTION_HEADER section;

	DWORD sec_size_aligned;
	DWORD fsize_old, fsize_new;
	DWORD index;
	DWORD p_sec_aligned;

	fhandle = ::CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
	shandle = ::CreateFileMappingA(fhandle, 0, PAGE_READWRITE, 0,0,0);
	mhandle = ::MapViewOfFile(shandle, FILE_MAP_ALL_ACCESS, 0,0,0);

	mz = (PIMAGE_DOS_HEADER)mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)mhandle + mz->e_lfanew);
	
	if (sec_size % pe64->OptionalHeader.SectionAlignment)
		sec_size_aligned = sec_size - (sec_size % pe64->OptionalHeader.SectionAlignment) + pe64->OptionalHeader.SectionAlignment;
	else
		sec_size_aligned = sec_size;

	fsize_old = ::GetFileSize(fhandle, 0);
	fsize_new = fsize_old + sec_size_aligned;

	::UnmapViewOfFile(mhandle);
	::CloseHandle(shandle);

	shandle = ::CreateFileMappingA(fhandle, 0, PAGE_READWRITE, 0, fsize_new, 0);
	mhandle = ::MapViewOfFile(shandle, FILE_MAP_ALL_ACCESS, 0,0, fsize_new);

	mz = (PIMAGE_DOS_HEADER)mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)mhandle + mz->e_lfanew);
	section = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->FileHeader.SizeOfOptionalHeader);

	index = pe64->FileHeader.NumberOfSections;

	p_sec_aligned = section[index-1].Misc.VirtualSize;
	if (p_sec_aligned % pe64->OptionalHeader.SectionAlignment)
		p_sec_aligned = p_sec_aligned - (p_sec_aligned % pe64->OptionalHeader.SectionAlignment) + pe64->OptionalHeader.SectionAlignment;

	section[index].VirtualAddress   = section[index-1].VirtualAddress + p_sec_aligned;
	section[index].PointerToRawData = fsize_old;
	section[index].SizeOfRawData    = sec_size_aligned;
	section[index].Misc.VirtualSize = sec_size_aligned;
	section[index].Characteristics  = 0xE0000020;
	::strncpy((char *)(&section[index].Name), sec_name, 8);

	pe64->FileHeader.NumberOfSections++;
	pe64->OptionalHeader.SizeOfImage += sec_size_aligned;

	::UnmapViewOfFile(mhandle);
	::CloseHandle(shandle);
	::CloseHandle(fhandle);
}

VOID DumpAndFixOep(DWORD pid, DWORD oepRva, LPSTR dumpFileName){
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_SECTION_HEADER section;
	DWORD SizeOfImage;
	DWORD sec_start, sec_size;
	DWORD dummy;
	HMODULE *lphModule;
	ULONG_PTR imagebase;
	ULONG_PTR EntryPoint;
	MODULEINFO modInfo;
	CRLString originalFileName;

	HANDLE fhandle, shandle, d_fhandle, d_shandle;
	PVOID mhandle, d_mhandle;
	HANDLE phandle;

	phandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	lphModule = (HMODULE *)GlobalAlloc(GPTR, 1024 * sizeof(HMODULE));

	::EnumProcessModules(phandle, lphModule, 1024 * sizeof(HMODULE), &dummy);
	::GetModuleInformation(phandle, lphModule[0], &modInfo, sizeof(MODULEINFO));
	imagebase = (ULONG_PTR)modInfo.lpBaseOfDll;
	if (!oepRva)
		EntryPoint = (ULONG_PTR)modInfo.EntryPoint - imagebase;
	else
		EntryPoint = oepRva;

	::GetModuleFileNameExA(phandle, lphModule[0], originalFileName.SetSize(MAX_PATH), MAX_PATH);
	::GlobalFree(lphModule);

	fhandle = ::CreateFileA(originalFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
	shandle = ::CreateFileMappingA(fhandle, 0, PAGE_READONLY, 0,0,0);
	mhandle = ::MapViewOfFile(shandle, FILE_MAP_READ, 0,0,0);

	mz = (PIMAGE_DOS_HEADER)mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)mhandle + mz->e_lfanew);

	SizeOfImage = pe64->OptionalHeader.SizeOfImage;
	if (SizeOfImage % pe64->OptionalHeader.SectionAlignment)
		SizeOfImage = SizeOfImage - (SizeOfImage % pe64->OptionalHeader.SectionAlignment) + pe64->OptionalHeader.SectionAlignment;

	d_fhandle = ::CreateFileA(dumpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0,0);
	d_shandle = ::CreateFileMappingA(d_fhandle, 0, PAGE_READWRITE, 0,SizeOfImage, 0);
	d_mhandle = ::MapViewOfFile(d_shandle, FILE_MAP_ALL_ACCESS, 0,0, SizeOfImage);

	::memcpy(d_mhandle, mhandle, pe64->OptionalHeader.SizeOfHeaders);

	::UnmapViewOfFile(mhandle);
	::CloseHandle(shandle);
	::CloseHandle(fhandle);

	mz = (PIMAGE_DOS_HEADER)d_mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)d_mhandle + mz->e_lfanew);
	section = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->FileHeader.SizeOfOptionalHeader);

	pe64->OptionalHeader.SizeOfImage = SizeOfImage;
	pe64->OptionalHeader.AddressOfEntryPoint = EntryPoint;
	pe64->OptionalHeader.SizeOfHeaders = 0x1000;

	for (ULONG i = 0; i < pe64->FileHeader.NumberOfSections; i++){
		sec_start = section[i].VirtualAddress;
		sec_size  = section[i].Misc.VirtualSize;

		if (sec_size % pe64->OptionalHeader.SectionAlignment)
			sec_size = sec_size - (sec_size % pe64->OptionalHeader.SectionAlignment) + pe64->OptionalHeader.SectionAlignment;
		
		::ReadProcessMemory(phandle, (PVOID)(imagebase+sec_start), (PVOID)((ULONG_PTR)d_mhandle + sec_start), sec_size, 0);
		section[i].VirtualAddress = sec_start;
		section[i].PointerToRawData = sec_start;
		section[i].SizeOfRawData    = sec_size;
		section[i].Misc.VirtualSize = sec_size;
		section[i].Characteristics  = 0xE0000020;

	}

	pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	::UnmapViewOfFile(d_mhandle);
	::CloseHandle(d_shandle);
	::CloseHandle(d_fhandle);

}
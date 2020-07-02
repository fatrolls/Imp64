// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
//erase some warning... I know why and what I'm using, and I don't need
//MSVC to tell me that what I'm using is not safe... when I know that
//it's safe!!!
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <commctrl.h>
#include <psapi.h>

// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <stdio.h>
#include <Commdlg.h>
#include "resource.h"
#include "pe64.h"
#include "..\\..\\RL\\RLString.h"


typedef struct{
	DWORD is_address;			
	DWORD is_apilen;
	DWORD is_dlllen;
	UCHAR is_dllname[256];
	UCHAR is_apiname[256];
}IMPORT_STRUCT, *PIMPORT_STRUCT;


// TODO: reference additional headers your program requires here
void InsertIntoCombox(LPSTR text);
void ListProcesses();

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    );

void CycleNameByDllName(LPSTR f_dllName, LPSTR o_dllName, PIMPORT_STRUCT pImport, HANDLE phandle);
BOOL IsResolved(PIMPORT_STRUCT pImport_c, DWORD rva);
ULONG ResolveApi64(DWORD pid, ULONG_PTR apiAddress, PIMPORT_STRUCT pImport);
DWORD CalculateImportSize(PIMPORT_STRUCT pi, DWORD *p_numIIDs);
PVOID BuildImportTable(DWORD section_rva, PIMPORT_STRUCT pi, DWORD iat_size, DWORD numIIDs);
VOID  AdjustFirstThunk(LPSTR dumpFileName);
void HandleForwards(PIMPORT_STRUCT pi, HANDLE phandle);
void InsertImportsIntoList(PIMPORT_STRUCT pImport);
bool AnalyzeImports(DWORD pid, LPSTR originalFileName);
void SortByAddress(PIMPORT_STRUCT pImport);
VOID DumpAndFixOep(DWORD pid, DWORD oepRva, LPSTR dumpFileName);
VOID AddSection(LPSTR fileName, DWORD sec_size, LPSTR sec_name);
DWORD CalculateImportSize(PIMPORT_STRUCT pi, DWORD *p_numIIDs);
PVOID BuildImportTable(DWORD section_rva, PIMPORT_STRUCT pi, DWORD iat_size, DWORD numIIDs);


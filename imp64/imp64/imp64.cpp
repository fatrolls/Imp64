// imp64.cpp : Defines the entry point for the application.
//

#include "stdafx.h"

INT_PTR CALLBACK DlgProc(HWND hDlg, UINT wmsg, WPARAM wparam, LPARAM lparam);
INT_PTR CALLBACK DlgProcApi(HWND hDlg, UINT wmsg, WPARAM wparam, LPARAM lparam);
INT_PTR CALLBACK DlgProcForwards(HWND hDlg, UINT wmsg, WPARAM wparam, LPARAM lparam);

HWND hList;
HWND hCombo;
extern DWORD ProcessIDs[4096];
PIMPORT_STRUCT g_pImport = NULL;
DWORD g_pid;

void InsertIntoCombox(LPSTR text)
{
	::SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)text);

}

void InsertImportsIntoList(PIMPORT_STRUCT pImport)
{
	PIMPORT_STRUCT pImport_temp;
	LVITEM		lvI;
	ULONG i;
	char rva[1024];
	::memset(&lvI, 0, sizeof(LVITEM));
	pImport_temp = pImport;

	while (pImport_temp->is_address){
		
		lvI.mask		= LVIF_TEXT;
		lvI.iItem		= ListView_GetItemCount(hList);
		lvI.iSubItem	= 0;
		lvI.pszText		= NULL;
		i = ListView_InsertItem(hList, &lvI);
		::sprintf_s((char *)&rva, 1024, "%.08X", pImport_temp->is_address);
		ListView_SetItemText(hList, i, 0, (LPSTR)&rva);
		ListView_SetItemText(hList, i, 1, (LPSTR)&pImport_temp->is_dllname);
		if (*(PULONG_PTR)&pImport_temp->is_apiname & 0x8000000000000000){
			::sprintf_s((char *)&rva, 1024, "%.08X", *(PULONG_PTR)&pImport_temp->is_apiname &~ 0x8000000000000000);
			ListView_SetItemText(hList, i, 2, (LPSTR)&rva);
		}else{
			ListView_SetItemText(hList, i, 2, (LPSTR)&pImport_temp->is_apiname);
		}
		pImport_temp++;
	}



}

ULONG htodw(LPSTR hex_string)
{
	ULONG ret_value = 0;
	PUCHAR hex;

	hex = (PUCHAR)hex_string;

	for (ULONG i = 0; i < 8; i++)
	{
		if (hex[i] == 0)
			break;
		
		ret_value = ret_value << 4;

		if (hex[i] >= '0' && hex[i] <= '9')
		{
			ret_value += hex[i] - '0';
			continue;
		}

		if (hex[i] >= 'a' && hex[i] <= 'f')
		{
			ret_value += hex[i] - 'a' + 10;
			continue;
		}

		if (hex[i] >= 'A' && hex[i] <= 'F')
		{
			ret_value += hex[i] - 'A' + 10;
			continue;
		}
	}


	return ret_value;

}

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	HANDLE hToken;

	::OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)){
		::MessageBoxA(0, "Can't activate SeDebugPrivilege", "imp64", 0x10);
	}
	::InitCommonControlsEx(NULL);
	::DialogBoxParamA(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), 0, DlgProc, 0);
	::ExitProcess(0);
}

INT_PTR CALLBACK DlgProc(HWND hDlg, UINT wmsg, WPARAM wparam, LPARAM lparam)
{
	char text[1024];
	ULONG_PTR	i;
	LVCOLUMN	lvC;
	NMHDR*		pnmh;
	NMITEMACTIVATE* pnmia;	
	HICON hIcon;
	CRLString dumpFileName;
	OPENFILENAME ofn;
	LPVOID lpMsgBuf;
	DWORD  new_sec_size, numIIDs;
	HANDLE fhandle, shandle;
	PVOID  mhandle;
	PPEHEADER64 pe64;
	PSECTION_HEADER section;
	ULONG index;
	PVOID imports;



	switch (wmsg){
		case WM_CLOSE:
			::EndDialog(hDlg, 0);
			return 1;
		case WM_INITDIALOG:
			hIcon = ::LoadIconA(GetModuleHandleA(0), MAKEINTRESOURCE(IDI_ICON1));
			SendMessageA(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
			hList = ::GetDlgItem(hDlg, IDC_LIST1);
			hCombo = ::GetDlgItem(hDlg, IDC_COMBO1);
			::memset(&lvC, 0, sizeof(LVCOLUMN));

			lvC.mask		= LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
			lvC.iSubItem	= 0;
			
			lvC.cx			= 100;
			lvC.pszText		= "RVA";
			lvC.fmt			= LVCFMT_LEFT;
			ListView_InsertColumn( hList, 0, &lvC );

			lvC.cx			= 175;
			lvC.pszText		= "dll";
			lvC.fmt			= LVCFMT_LEFT;
			ListView_InsertColumn( hList, 1, &lvC );

			lvC.cx			= 300;
			lvC.pszText		= "API";
			lvC.fmt			= LVCFMT_LEFT;
			ListView_InsertColumn( hList, 2, &lvC );

			EnableWindow(GetDlgItem(hDlg, IDC_ANALYZE), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_DUMPFILE), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_FIXDUMP), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_FORWARDS), FALSE);
			SetDlgItemTextA(hDlg, IDC_OEPRVA, "00000000");
			SetDlgItemTextA(hDlg, IDC_STATUS, "Ready...");
			ListProcesses();
			
			return 1;
		case WM_COMMAND:
			switch (LOWORD(wparam)){
				case IDC_COMBO1:
					if (HIWORD(wparam) == CBN_SELENDOK){
						i = SendMessageA(hCombo, CB_GETCURSEL, 0, 0);
						SendMessageA(hCombo, CB_GETLBTEXT, i, (LPARAM)&text);
						SendMessageA(hList, LVM_DELETEALLITEMS, 0,0);
						::VirtualFree(g_pImport, 0, MEM_DECOMMIT);
						g_pImport = NULL;
						g_pid = htodw((LPSTR)&text);
						if (AnalyzeImports(htodw((LPSTR)&text), (LPSTR)&text[11])){
							::SetDlgItemTextA(hDlg, IDC_STATUS, "Analyze done...");
						}else{
							::SetDlgItemTextA(hDlg, IDC_STATUS, "Analyze failed...");
						}
						EnableWindow(GetDlgItem(hDlg, IDC_ANALYZE), TRUE);
						EnableWindow(GetDlgItem(hDlg, IDC_DUMPFILE), TRUE);
						EnableWindow(GetDlgItem(hDlg, IDC_FIXDUMP), TRUE);
						EnableWindow(GetDlgItem(hDlg, IDC_FORWARDS), TRUE);
						return 1;
					}
					return 0;
				case IDC_ABOUT:
					::MessageBoxA(hDlg, "imp64 - tool to fix imports for x64 targets\n\n(c) 2008 deroko of ARTeam","about",0);
					return 1;
				case IDC_FORWARDS:
					DialogBoxParamA(GetModuleHandleA(0), MAKEINTRESOURCE(IDD_DIALOG3), hDlg, DlgProcForwards, 0);
					SendMessageA(hList, LVM_DELETEALLITEMS, 0,0);
					InsertImportsIntoList(g_pImport);
					return 1;
				case IDC_DUMPFILE:
					::memset(&ofn, 0, sizeof(OPENFILENAME));
					dumpFileName.SetSize(MAX_PATH);

					ofn.lStructSize = sizeof(OPENFILENAME);
					ofn.lpstrFilter = "Executable files\0*.exe\0\0";
					ofn.lpstrFile = (LPSTR)dumpFileName;
					ofn.nMaxFile = MAX_PATH;
					ofn.hwndOwner = hDlg;
					::strcpy_s((char *)dumpFileName.GetString(), MAX_PATH, "dumped.exe");

					if (GetSaveFileNameA(&ofn)){
						::memset(&text, 0, 1024);
						GetDlgItemTextA(hDlg, IDC_OEPRVA, (LPSTR)&text, 8);
						::DumpAndFixOep(g_pid, htodw((LPSTR)&text), dumpFileName);
						::SetDlgItemTextA(hDlg, IDC_STATUS, "Dumping done...");
					}
					return 1;
				case IDC_FIXDUMP:
					::memset(&ofn, 0, sizeof(OPENFILENAME));
					dumpFileName.SetSize(MAX_PATH);

					ofn.lStructSize = sizeof(OPENFILENAME);
					ofn.lpstrFilter = "Executable files\0*.exe\0\0";
					ofn.lpstrFile = (LPSTR)dumpFileName;
					ofn.nMaxFile = MAX_PATH;
					ofn.hwndOwner = hDlg;
					::strcpy_s((char *)dumpFileName.GetString(), MAX_PATH, "dumped.exe");

					if (GetSaveFileNameA(&ofn)){
						new_sec_size = CalculateImportSize(g_pImport, &numIIDs);
						AddSection(dumpFileName, new_sec_size, ".imp64");

						fhandle = ::CreateFileA(dumpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
						shandle = ::CreateFileMappingA(fhandle, 0, PAGE_READWRITE, 0,0,0);
						mhandle = ::MapViewOfFile(shandle, FILE_MAP_ALL_ACCESS, 0,0,0);

						pe64 = (PPEHEADER64)((ULONG_PTR)mhandle + PIMAGE_DOS_HEADER(mhandle)->e_lfanew);
						section = (PSECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->pe_sizeofoptionalheader);
						index = pe64->pe_numberofsections - 1;
						
						imports = BuildImportTable(section[index].sh_virtualaddress, g_pImport, new_sec_size, numIIDs);
						::memcpy((void *)((ULONG_PTR)mhandle + section[index].sh_pointertorawdata),
								 imports,
								 new_sec_size);
						pe64->pe_import = section[index].sh_virtualaddress;
						pe64->pe_importsize = numIIDs * sizeof(IMAGE_IMPORT_DESCRIPTOR);

						VirtualFree(imports, 0, MEM_DECOMMIT);
						UnmapViewOfFile(mhandle);
						CloseHandle(shandle);
						CloseHandle(fhandle);
						::SetDlgItemTextA(hDlg, IDC_STATUS, "Imports fixed...");


					}
					return 1;

				default:
					return 0;
			}

		case WM_NOTIFY:
			pnmh = (NMHDR*)lparam;
            if((pnmh->hwndFrom == hList) && (pnmh->code == LVN_ITEMACTIVATE))
            {
                pnmia = (NMITEMACTIVATE*) lparam;
				i = pnmia->iItem;
				
				ListView_GetItemText(hList, i, 0, (LPSTR)&text, 256);
				//MessageBoxA(hDlg, (LPSTR)&text, 0, 0);
				::DialogBoxParamA(::GetModuleHandleA(0), MAKEINTRESOURCE(IDD_DIALOG2), hDlg, DlgProcApi, (LPARAM)i);
                // This is when an item is "activated", or double-clicked.
				// Here we get index, which is index into IMPORT_STRUCT and allow
				// user to change imports if required!!
				SendMessageA(hList, LVM_DELETEALLITEMS, 0,0);
				InsertImportsIntoList(g_pImport);
                return 1;
			}
			return 0;
		default:
			return 0;

	}
	return 0;
}

ULONG_PTR index_is;
INT_PTR CALLBACK DlgProcApi(HWND hDlg, UINT wmsg, WPARAM wparam, LPARAM lparam){
	char local_buffer[1024];

	switch (wmsg){
		case WM_INITDIALOG:
			index_is = (ULONG_PTR)lparam;
			::sprintf_s((char *)local_buffer, 1024, "%.08X", g_pImport[index_is].is_address);
			SetDlgItemTextA(hDlg, IDC_RVA, (LPSTR)&local_buffer);
			SetDlgItemTextA(hDlg, IDC_DLL, (LPSTR)&g_pImport[index_is].is_dllname);
			if (*(PULONG_PTR)&g_pImport[index_is].is_apiname & 0x8000000000000000){
				::sprintf_s((char *)&local_buffer, 1024, "%.08X", (*(PULONG_PTR)&g_pImport[index_is].is_apiname) &~ 0x8000000000000000);
				SetDlgItemTextA(hDlg, IDC_API, (LPSTR)&local_buffer);
			}else
				SetDlgItemTextA(hDlg, IDC_API, (LPSTR)&g_pImport[index_is].is_apiname);		
			return 1;
		case WM_CLOSE:
			EndDialog(hDlg, 0);
			return 1;
		case WM_COMMAND:
			if (wparam == IDOK){
				GetDlgItemTextA(hDlg, IDC_RVA, (LPSTR)&local_buffer, 1024);
				g_pImport[index_is].is_address = htodw((LPSTR)&local_buffer);
				g_pImport[index_is].is_dlllen  = GetDlgItemTextA(hDlg, IDC_DLL, (LPSTR)&local_buffer, 1024) + 1;
				::strcpy_s((char *)&g_pImport[index_is].is_apiname, 256, (char *)&local_buffer);
				if (*(PULONG_PTR)&g_pImport[index_is].is_apiname & 0x8000000000000000){
					g_pImport[index_is].is_apilen = 8;
					GetDlgItemTextA(hDlg, IDC_API, (LPSTR)&local_buffer, 1024);
					*(DWORD *)&g_pImport[index_is].is_apiname[4] = htodw((LPSTR)&local_buffer);
				}else{
					g_pImport[index_is].is_apilen = GetDlgItemTextA(hDlg, IDC_API, (LPSTR)&local_buffer, 1024) + 1;
					::strcpy_s((char *)&g_pImport[index_is].is_apiname, 256, (char *)&local_buffer);
				}

				EndDialog(hDlg, 0);
				return 1;
			}
			else if (wparam == IDCANCEL)
				EndDialog(hDlg, 0);
			return 1;
		default:
			return 0;
	}



	return 0;
}

INT_PTR CALLBACK DlgProcForwards(HWND hDlg, UINT wmsg, WPARAM wparam, LPARAM lparam){
	HANDLE phandle;
	char old_dllName[1024];
	char new_dllName[1024];
	char dll_string[1024];
	PIMPORT_STRUCT pImport_temp;


	switch (wmsg){
		case WM_INITDIALOG:
			SetDlgItemTextA(hDlg, IDC_DLLNAME, "kernel32.dll");
			SetDlgItemTextA(hDlg, IDC_DLLSTRING, "ntdll.dll");
			SetDlgItemTextA(hDlg, IDC_NAME, "NTDLL");
			return 1;
		case WM_COMMAND:
			if (wparam == IDOK){
				GetDlgItemTextA(hDlg, IDC_DLLNAME, (LPSTR)&new_dllName, 1024);
				GetDlgItemTextA(hDlg, IDC_DLLSTRING, (LPSTR)&old_dllName, 1024);
				GetDlgItemTextA(hDlg, IDC_NAME, (LPSTR)&dll_string, 1024);

				phandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_pid);
				
				if (g_pImport){
					pImport_temp = g_pImport;
						while(pImport_temp->is_address){
							if (!::strnicmp((char *)&pImport_temp->is_dllname, (LPSTR)&old_dllName, pImport_temp->is_dlllen))
								CycleNameByDllName((LPSTR)&new_dllName, (LPSTR)&dll_string, pImport_temp, phandle);
							pImport_temp++;
						}
		

				}
				::CloseHandle(phandle);
				EndDialog(hDlg, 0);
			}else if (wparam == IDCANCEL){
				EndDialog(hDlg, 0);
				return 1;
			}
			return 0;
		case WM_CLOSE:
			EndDialog(hDlg, 0);
			return 1;
		default:
			return 0;
	}
	return 0;
}
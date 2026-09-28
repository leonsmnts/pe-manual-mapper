#pragma once

#include <windows.h>

typedef HMODULE (__stdcall* f_LoadLibraryA)(LPCSTR lpLibFileName);
typedef DWORD (__stdcall* f_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL (APIENTRY* f_DllMain)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

typedef struct _PARAMS_TO_PASS {
	DWORD actualBase;
	DWORD deltaBase;
	DWORD baseRelocTable;
	DWORD importDirectory;
	f_LoadLibraryA _LoadLibraryA;
	f_GetProcAddress _GetProcAddress;
	f_DllMain _DllMain;
} PARAMS_TO_PASS;

bool ManualMap(const char* procName, const char* dllPath);

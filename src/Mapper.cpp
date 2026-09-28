#include "Mapper.hpp"

#include <iostream>
#include <TlHelp32.h>

bool checkDllFormat(BYTE* dllBytes, IMAGE_NT_HEADERS* peHeader);
void hexdump(BYTE* dllBytes, DWORD fileSize);
DWORD WINAPI remoteCode(LPVOID lpParameter);

bool OpenSpecifiedProcess(const char* procName);
bool CopySpecifiedDllIntoMemory(const char* dllPath);
bool CopySpecifiedDllIntoProcess(DWORD* actualBase, IMAGE_OPTIONAL_HEADER** optionalHeaderPtr);
bool SetupRemoteCode(DWORD actualBase, IMAGE_OPTIONAL_HEADER* optionalHeader, LPVOID* baseOfRemoteFunction);
bool ExecuteRemoteCode(LPVOID baseOfRemoteFunction, DWORD actualBase);
void Cleanup(LPVOID baseOfRemoteFunction);

HANDLE hProcess = 0;
BYTE* dllBytes = nullptr; // only free at end, because of pointers pointing into this region!

bool ManualMap(const char* procName, const char* dllPath) {
	DWORD actualBase;
	IMAGE_OPTIONAL_HEADER* optionalHeader;
	LPVOID baseOfRemoteFunction = 0;

	if (!OpenSpecifiedProcess(procName)) {
		printf("Error in OpenSpecifiedProcess()\n");
		Cleanup(baseOfRemoteFunction);
		return false;
	}

	if (!CopySpecifiedDllIntoMemory(dllPath)) {
		printf("Error in CopySpecifiedDllIntoMemory()\n");
		Cleanup(baseOfRemoteFunction);
		return false;
	}

	if (!CopySpecifiedDllIntoProcess(&actualBase, &optionalHeader)) {
		printf("Error in CopySpecifiedDllIntoProcess()\n");
		Cleanup(baseOfRemoteFunction);
		return false;
	}

	if (!SetupRemoteCode(actualBase, optionalHeader, &baseOfRemoteFunction)) {
		printf("Error in SetupRemoteCode()\n");
		Cleanup(baseOfRemoteFunction);
		return false;
	}

	if (!ExecuteRemoteCode(baseOfRemoteFunction, actualBase)) {
		printf("Error in ExecuteRemoteCode()\n");
		Cleanup(baseOfRemoteFunction);
		return false;
	}
	// TODO: Also do somthing for TLS (thread local storage) in remote code ?!

	Cleanup(baseOfRemoteFunction);
	return true;
}

bool OpenSpecifiedProcess(const char* procName) {
	HANDLE hSnapshot;
	PROCESSENTRY32 processIter;
	DWORD targetPid = 0; // PID 0 is <idle>, safe as "not found"
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Could not create Snapshot of Processes!\n");
		return false;
	}

	processIter.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &processIter);
	do {
		if (!strcmp(procName, processIter.szExeFile)) {
			targetPid = processIter.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &processIter));

	CloseHandle(hSnapshot);

	if (targetPid == 0) {
		printf("Did not find specified process in the Snapshot!\n");
		return false;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
	if (!hProcess) {
		printf("Could not retrieve a handle to specified process!\n");
		return false;
	}
	return true;
}

bool CopySpecifiedDllIntoMemory(const char* dllPath) {
	HANDLE hDll;
	LARGE_INTEGER LIFileSize;
	DWORD fileSize;
	DWORD bytesRead;
	
	hDll = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDll == INVALID_HANDLE_VALUE) {
		printf("Could not open DLL-File!\n");
		printf("Maybe it does not exist?\n");
		printf("Error Code: 0x%X\n", GetLastError());
		return false;
	}

	if (!GetFileSizeEx(hDll, &LIFileSize)) {
		printf("Could not retrieve the size of the DLL!\n");
		printf("Error Code: 0x%X\n", GetLastError());
		CloseHandle(hDll);
		return false;
	}

	fileSize = LIFileSize.QuadPart;
	dllBytes = (BYTE*)malloc(fileSize);
	if (!dllBytes) {
		printf("Error on allocating memory for the DLL!\n");
		CloseHandle(hDll);
		return false;
	}

	if (!ReadFile(hDll, dllBytes, fileSize, &bytesRead, NULL)) {
		printf("Could not read the DLL!\n");
		printf("Error Code: 0x%X\n", GetLastError());
		CloseHandle(hDll);
		return false;
	}

	CloseHandle(hDll);
	return true;
}

bool CopySpecifiedDllIntoProcess(DWORD* actualBase, IMAGE_OPTIONAL_HEADER** optionalHeaderPtr) {
	SIZE_T bytesWritten;
	int i;
	
	DWORD offsetToPEHeader = *((DWORD*)(dllBytes + 0x3c));
	IMAGE_NT_HEADERS* peHeader = ((IMAGE_NT_HEADERS*)(&dllBytes[offsetToPEHeader]));
	IMAGE_FILE_HEADER* fileHeader = &peHeader->FileHeader;
	*optionalHeaderPtr = &peHeader->OptionalHeader;
	IMAGE_OPTIONAL_HEADER* optionalHeader = *optionalHeaderPtr;
	IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(((BYTE*)optionalHeader) + fileHeader->SizeOfOptionalHeader);

	DWORD sizeOfImage = optionalHeader->SizeOfImage;
	WORD numberOfSections = fileHeader->NumberOfSections;

	if (!checkDllFormat(dllBytes, peHeader)) {
		printf("Error with DLL format!\n");
		return false;
	}

	*actualBase = (DWORD)VirtualAllocEx(hProcess, (LPVOID)(optionalHeader->ImageBase), sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!(*actualBase)) {
		*actualBase = (DWORD)VirtualAllocEx(hProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!(*actualBase)) {
			printf("Could not allocate Memory in the specified Process (for DLL)!\n");
			printf("Error Code: 0x%X\n", GetLastError());
			return false;
		}
	}

	for (i = 0; i < numberOfSections; i++, sectionHeader++) {
		printf("%-8s\n", sectionHeader->Name);
		printf("0x%x\n", sectionHeader->SizeOfRawData); // copy so many bytes
		printf("0x%x\n", sectionHeader->VirtualAddress); // map to here in addr space
		printf("pointer in file: 0x%x\n\n", sectionHeader->PointerToRawData);
		if (sectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProcess, (LPVOID)((*actualBase) +sectionHeader->VirtualAddress), (LPCVOID)(dllBytes + sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData, &bytesWritten) || bytesWritten != sectionHeader->SizeOfRawData) {
				if (bytesWritten != sectionHeader->SizeOfRawData) {
					printf("The specified amount of bytes to Write into the target process could not be written.\n");
				}
				else {
					printf("Writing a Section into target Process failed!\n");
					printf("Error Code: 0x%X\n", GetLastError());
				}

				VirtualFreeEx(hProcess, (LPVOID)(*actualBase), 0, MEM_RELEASE);
				return false;
			}
		}
	}
	return true;
}

bool SetupRemoteCode(DWORD actualBase, IMAGE_OPTIONAL_HEADER* optionalHeader, LPVOID* baseOfRemoteFunction) {
	PARAMS_TO_PASS params{ 0 };
	DWORD preferredBase = optionalHeader->ImageBase;

	params.actualBase = actualBase;
	params.deltaBase = actualBase - preferredBase;
	params.baseRelocTable = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	params.importDirectory = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	params._LoadLibraryA = LoadLibraryA;
	params._GetProcAddress = (f_GetProcAddress)GetProcAddress;
	params._DllMain = (f_DllMain)(actualBase + optionalHeader->AddressOfEntryPoint);

	// TODO:
	// alloc mem for my function in remote process
	// copy params AND my function over to remote proc
	*baseOfRemoteFunction = VirtualAllocEx(hProcess, 0, optionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!(*baseOfRemoteFunction)) {
		printf("Could not allocate Memory in the specified Process (for remoteCode func)!\n");
		printf("Error Code: 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, (LPVOID)actualBase, 0, MEM_RELEASE);
		return false;
	}

	// Hopefully no need to Error-Check since already written before. But maybe add sometime in the future!
	WriteProcessMemory(hProcess, *baseOfRemoteFunction, &params, sizeof(params), NULL);
	WriteProcessMemory(hProcess, ((BYTE*)(*baseOfRemoteFunction) + sizeof(params)), remoteCode, 0x1000, NULL);
	return true;
}

bool ExecuteRemoteCode(LPVOID baseOfRemoteFunction, DWORD actualBase) {
	HANDLE remoteThreadHandle;
	DWORD exitCodeThread;

	remoteThreadHandle = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)((PBYTE)baseOfRemoteFunction + sizeof(PARAMS_TO_PASS)), baseOfRemoteFunction, 0, 0);
	if (!remoteThreadHandle) {
		printf("Creating a Thread in the target Process failed (for executing remoteCodeFunc)!\n");
		printf("Error Code: 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, (LPVOID)actualBase, 0, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(remoteThreadHandle, INFINITE); // joins on thread
	GetExitCodeThread(remoteThreadHandle, &exitCodeThread);
	// TODO: maybe make this more verbose // multiple error codes
	if (exitCodeThread != 0) {
		printf("exitCodeThread: 0x%x\n", exitCodeThread);
		printf("The remote Thread failed on something!\n");
		CloseHandle(remoteThreadHandle);
		VirtualFreeEx(hProcess, (LPVOID)actualBase, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(remoteThreadHandle);
	return true;
}

void Cleanup(LPVOID baseOfRemoteFunction) {
	if (baseOfRemoteFunction) {
		VirtualFreeEx(hProcess, baseOfRemoteFunction, 0, MEM_RELEASE);
	}
	if (dllBytes) {
		free(dllBytes);
		dllBytes = nullptr;
	}
	if (hProcess) {
		CloseHandle(hProcess);
		hProcess = 0;
	}
}

DWORD WINAPI remoteCode(LPVOID lpParameter) {
	// More info: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
	
	int i;
	PARAMS_TO_PASS* params = (PARAMS_TO_PASS*)lpParameter;

	DWORD actualBase = params->actualBase;
	DWORD deltaBase = params->deltaBase;
	IMAGE_BASE_RELOCATION* currentRelocation;
	DWORD amountOfRelocations;
	DWORD baseRelocTable = params->baseRelocTable;

	// Relocation only needed if Base is not as expected.
	if (deltaBase) {
		for (currentRelocation = (IMAGE_BASE_RELOCATION*)(actualBase + baseRelocTable); *(DWORD*)currentRelocation;) {
			amountOfRelocations = (currentRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relocs = (WORD*)(currentRelocation + 1);
			for (i = 0; i < amountOfRelocations; i++, relocs++) {
				DWORD relocOffset = (*relocs) & 0xfff;
				DWORD relocType = (*relocs) >> 12;
				if (relocType == IMAGE_REL_BASED_HIGHLOW) {
					DWORD relocationAddress = relocOffset + currentRelocation->VirtualAddress + actualBase;
					*(DWORD*)relocationAddress += deltaBase;
				}
			}
			currentRelocation = (IMAGE_BASE_RELOCATION*)(((DWORD)currentRelocation) + currentRelocation->SizeOfBlock);
		}
	}

	// now fix import table
	//TODO: We assume that all Imports are by name, not by ordinal. Potentially add support in the future.
	//      Check MSB of each ILT entry (-> Ordinal/Name flag).
	IMAGE_IMPORT_DESCRIPTOR *importDir = (IMAGE_IMPORT_DESCRIPTOR*)(actualBase + params->importDirectory);
	const char* dllToImportName;
	HMODULE hModule;
	IMAGE_IMPORT_BY_NAME **nameArrayPtr;
	DWORD *thunkArrayPtr;

	for (; importDir->Name; importDir++) {
		thunkArrayPtr = (DWORD*)(actualBase + importDir->FirstThunk);
		
		// Some binaries can contain a zeroed out ILT (OriginalFirstThunk), in which case we should use the IAT (FirstThunk) instead.
		// https://www.sunshine2k.de/reversing/tuts/tut_rvait.htm#:~:text=Note%3A%20Some%20linker%20set%20OriginalFirstThunk%20to%20zero%2C%20then%20we%20use%20FirstThunk
		// https://www.gbppr.net/cracking/iczelion/pe-tut6.html#:~:text=If%20OriginalFirstThunk%20is%20zero%2C%20use%20the%20value%20in%20FirstThunk%20instead
		if (importDir->OriginalFirstThunk) {
			nameArrayPtr = (IMAGE_IMPORT_BY_NAME**)(actualBase + importDir->OriginalFirstThunk);
		}
		else {
			nameArrayPtr = (IMAGE_IMPORT_BY_NAME**)thunkArrayPtr;
		}
		
		dllToImportName = (const char*)(actualBase + importDir->Name);
		hModule = params->_LoadLibraryA(dllToImportName);
		if (!hModule) {
			return -1;
		}

		while (*thunkArrayPtr) {
			*thunkArrayPtr = params->_GetProcAddress(hModule, ((*nameArrayPtr)->Name) + actualBase);
			nameArrayPtr++;
			thunkArrayPtr++;
		}
	}

	params->_DllMain((HMODULE)actualBase, DLL_PROCESS_ATTACH, 0);
	return 0;
	// what about TLS now?
}

bool checkDllFormat(BYTE* dllBytes, IMAGE_NT_HEADERS *peHeader) {
	if (dllBytes[0] != '\x4D' || dllBytes[1] != '\x5A') {
		printf("DLL does not start with 'MZ'!\n");
		return false;
	}
	if (peHeader->Signature != 0x4550) {
		printf("PE-Header Signature incorrect.\n");
		printf("Expected:  0x50 0x45 0x00 0x00\n");
		printf("But was:   0x%02x 0x%02x 0x%02x 0x%02x\n", *((BYTE*)peHeader), *((BYTE*)peHeader + 1), *((BYTE*)peHeader + 2), *((BYTE*)peHeader + 3));
		return false;
	}
	
	#ifdef _WIN64
	if (peHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("DLL is not for x64 Processor, but Injector is compiled for x64!\n");
		return false;
	}
	#else
	if (peHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		printf("DLL is not for x86 Processor, but Injector is compiled for x86!\n");
		return false;
	}
	#endif

	if (!(peHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		printf("The specified File is NOT a DLL!\n");
		printf("PE-Header > FileHeader > Characteristics\n");
		return false;
	}

	if (peHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		printf("The specified file is either a ROM image or an executable image that is not made for the current platform!\n");
		return false;
	}

	return true;
}

void hexdump(BYTE* dllBytes, DWORD fileSize) {
	for (int i = 0; i < fileSize; i += 16) {
		printf("0x%#08x   ", i);
		for (int j = 0; j < 16; j++) {
			printf("%02x ", dllBytes[i + j]);
		}
		printf("\n");
	}
}

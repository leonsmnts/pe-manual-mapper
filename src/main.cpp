#include "Mapper.hpp"

#include <iostream>
#include <cstdlib>

char dllPath[512];
char processName[512];

bool checkInput();
void removeLineFeedFromInput();
void receiveInput();

int main() {
	receiveInput();
	removeLineFeedFromInput();

	if (!checkInput()) {
		printf("Entered invalid Input. Exiting...\n");
		Sleep(2000);
		return 1;
	}

	printf("%-28s%s\n", "Process to attach to:", processName);
	printf("%-28s%s\n\n", "Dll to inject:", dllPath);

	if (!ManualMap(processName, dllPath)) {
		printf("Error on injection.\n");
		printf("\n");
		system("pause");
		return 1;
	}

	printf("Successfully Injected!\n");
	Sleep(4000);
	return 0;
}

void receiveInput() {
	printf("What process to inject into?\n>>> ");
	if (!fgets(processName, sizeof(processName), stdin)) {
		printf("Error on fgets(process)?\n");
		printf("Exiting...\n");
		Sleep(2000);
		exit(1);
	}
	printf("\nPath to the DLL to inject:\n>>> ");
	if (!fgets(dllPath, sizeof(dllPath), stdin)) {
		printf("Error on fgets(dllPath)?\n");
		printf("Exiting...\n");
		Sleep(2000);
		exit(1);
	}
	printf("\n");
}

void removeLineFeedFromInput() {
	int lenProc = strlen(processName);
	int lenPath = strlen(dllPath);

	processName[lenProc - 1] = processName[lenProc - 1] == 0x0a ? 0 : processName[lenProc - 1];
	dllPath[lenPath - 1] = dllPath[lenPath - 1] == 0x0a ? 0 : dllPath[lenPath - 1];
}

bool checkInput() {
	int lenPath = strlen(dllPath);

	if (lenPath < 4 || strcmp((const char*)(&dllPath[lenPath - 4]), ".dll")) {
		printf("The specified path is not a path to a '.dll'-file.\n");
		return false;
	}

	return true;
}

#include <windows.h>
#include <stdio.h>

// Loads a DLL without starting its DllMain function. Useful if you want
// to attach a debugger and follow execution step-by-step from DllMain.

// For now, we use LoadLibraryEx with option DONT_RESOLVE_DLL_REFERENCES.
// This will imply that DllMain will not execute upon process/thread
// initialization and termination. We use a standard sequence to build
// the IAT and apply relocations. The code may break if DLL uses SEH.
// In the future, we may borrow the code of MemoryModulePP to this end
// so as to achieve better compatibility and ease-of-use.

DWORD parseExports(PBYTE pImageBase);
void processImports(PBYTE pImageBase);

typedef BOOL(WINAPI pDllMain)(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved);

int main(int argc, char** argv) {
	if (argc < 2) {
		printf("Syntax: %s <path to DLL> [<dependencies>]\n", argv[0]);
		exit(1);
	}
	char* dllToLoad = argv[1];
	int deps = argc - 2;
	while (deps > 0) {
		char* depPath = argv[argc - deps--];
		printf("> Loading dependency: %s\n", depPath);
		HMODULE hDepDLL = LoadLibraryA(depPath);
		if (hDepDLL) printf("+ Loaded at: 0x%p\n", hDepDLL);
		else {
			printf("! Failed! Please check the path. Exiting...\n");
			exit(1);
		}
	}
	
	printf("> Loading DLL without starting DllMain...\n");
	HMODULE hDLL = LoadLibraryExA(dllToLoad, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hDLL) {
		printf("! Failed! Please check the path. Exiting...\n");
		exit(1);
	}

	ULONG_PTR dllBase = (ULONG_PTR)hDLL;

	printf("> Building the IAT for the DLL...\n");
	processImports((PBYTE)dllBase);

	// TODO add check on x64 bogus signature 'pop r10' 
	ULONG_PTR dllHeader = dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew;
	ULONG_PTR dllEntryPoint = dllBase + ((PIMAGE_NT_HEADERS)dllHeader)->OptionalHeader.AddressOfEntryPoint;

	//FARPROC dllMain = GetProcAddress(hDLL, "DllMain");
	printf("+ DLL loaded at: 0x%p\n", hDLL);
	printf("+ Address of DLL entry point: 0x%x\n", dllEntryPoint);
	printf("> Parsing export table now\n");
	DWORD rvaDllMain = parseExports((PBYTE)dllBase);

	printf("? Choose one of the following options:\n");
	printf("- enter the RVA of the function to execute (call with no arguments)\n");
	if (rvaDllMain) {
		printf("- enter 0 to invoke DllMain(self, DLL_PROCESS_ATTACH, 0)\n");
	}
	printf("- press CTRL-C to exit\n");
	
	char data[8];
	if (!fgets(data, sizeof(data), stdin)) {
		printf("! Unknown error or invalid input, exiting...\n");
		exit(1);
	}
	DWORD choice = strtol(data, NULL, 16);

	printf("> Upon pressing any key, I will call the requested function.\n");
	printf("! Waiting for your keystroke. Enjoy the debugging...\n");
	system("pause");

	if (choice == 0 && rvaDllMain) {
		pDllMain* myDllMain = (pDllMain*)(dllBase + rvaDllMain);
		myDllMain(hDLL, DLL_PROCESS_ATTACH, 0);
	}
	else {
		FARPROC someFunction = (FARPROC)(dllBase+choice);
		someFunction();
	}

	printf("> Function started. Press CTRL-C or ENTER to exit the process...\n");
	system("pause");

	return 0;
}


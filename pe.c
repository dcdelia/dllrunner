#include <windows.h>
#include <stdio.h>

// displays exports and returns RVA of DllMain if found
DWORD parseExports(PBYTE pImageBase) {
	const BOOL isDebug = FALSE;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0; // redundant

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);
	if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		fprintf(stderr, "IMAGE_NT_OPTIONAL_HDR64_MAGIC not supported yet\n");
		return 0;
	}

	DWORD exportDirRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportDirSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pImageBase + exportDirRVA);
	PDWORD pdwFunctions = (PDWORD)(pImageBase + pExportDir->AddressOfFunctions);
	PWORD pwOrdinals = (PWORD)(pImageBase + pExportDir->AddressOfNameOrdinals);
	PDWORD pszFuncNames = (PDWORD)(pImageBase + pExportDir->AddressOfNames);

	if (isDebug) {
		printf("Export directory at: 0x%p\n", pExportDir);
		printf("AddressOfFunctons at: 0x%p\n", pdwFunctions);
		printf("AddressOfNameOrdinals at: 0x%p\n", pwOrdinals);
		printf("AddressOfNames at: 0x%p\n", pszFuncNames);
	}
	
	DWORD unnamed = pExportDir->NumberOfFunctions - pExportDir->NumberOfNames;

	if (unnamed) {
		printf("> Unnamed exports: %d\n", unnamed);
		printf("! Please look their offsets up using an external tool :-/\n");
	}

	DWORD rvaDllMain = 0;

	for (size_t i = 0; i < pExportDir->NumberOfNames; ++i) {
		DWORD addr_name = pszFuncNames[i];
		DWORD rva = pdwFunctions[pwOrdinals[i]];

		// discard forwarders
		if (exportDirRVA <= rva && rva < exportDirRVA+ exportDirSize) {
			continue;
		}

		// discard storage
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader);
		BOOL isCode = FALSE;
		for (size_t j = 0; j < pNtHeader->FileHeader.NumberOfSections; j++, section++) {
			DWORD size = section->Misc.VirtualSize;
			if (size == 0) size = section->SizeOfRawData;
			if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size))) {
				isCode = section->Characteristics & IMAGE_SCN_CNT_CODE;
				break;
			}
		}
		
		if (!isCode) continue;

		char* name = (char*)(pImageBase + addr_name);
		printf("+ %s with RVA %x (0x%p)\n", name, rva, pImageBase+rva);

		if (!strcmp(name, "_DllMain@12")) rvaDllMain = rva;
	}

	return rvaDllMain;
}


// process INT and build IAT for current module
// code borrowed from a popular reflective loader
// credits: Stephen Fewer and injectAllTheThings 

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_32( name )*(DWORD *)(name)

void processImports(PBYTE pImageBase) {
	ULONG_PTR uiBaseAddress = (ULONG_PTR)pImageBase;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return; // redundant

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)pNtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// addition: play with page protection
	DWORD oldProtection;
	ULONG_PTR iatStart = uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk;
	printf("> Making IAT temporarily writable at: 0x%x\n", iatStart);
	VirtualProtect((LPVOID)iatStart, 4096, PAGE_READWRITE, &oldProtection);

	// iterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		LPCSTR dllName = (LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name);
		HMODULE hDll = GetModuleHandleA(dllName);

		if (!hDll) {
			printf("> Using LoadLibraryA for dependency: %s\n", dllName);
			hDll = LoadLibraryA(dllName);
			if (!hDll) {
				printf("! Failed. Try to provide full path as extra argument to dllrunner\n");
				exit(1);
			}
		}

		ULONG_PTR uiLibraryAddress = (ULONG_PTR)hDll;

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// iterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				ULONG_PTR uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				ULONG_PTR uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				ULONG_PTR uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				LPCSTR api =(LPCSTR)(((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
				ULONG_PTR apiAddr = (ULONG_PTR)GetProcAddress(hDll, api);
				if (!apiAddr) {
					printf("! GetProcAddress failed for %s. Exiting\n", api);
					exit(1);
				}
				DEREF(uiValueA) = apiAddr;
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// restore page protection
	VirtualProtect((LPVOID)iatStart, 4096, oldProtection, NULL);
}
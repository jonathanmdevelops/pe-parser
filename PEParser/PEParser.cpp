// PeParser.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include "PeParser.h"

int _tmain(int argc, _TCHAR* argv[])
{

    HANDLE hFile;
    TCHAR pszFilePath[MAX_PATH];

    LPVOID lpFileContent;
    DWORD nNumberOfBytesToRead;
    DWORD nNumberOfBytesRead;

	PIMAGE_DOS_HEADER piDosHeader = {};
	PIMAGE_NT_HEADERS piNtHeaders = {};
	PIMAGE_SECTION_HEADER piSectionHeader = {};

    if (argc != 2)
    {
        std::cout << "Incorrect number of arguments, a single file path is required." << std::endl;
        return 1;
    }

    if (GetFullPathName(argv[1], MAX_PATH, pszFilePath, NULL) == 0)
    {
        std::cerr << "Failed to get full path of file " << argv[2] << "." << std::endl;
        return 1;
    }

    hFile = CreateFile(pszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to open file at " << pszFilePath << "." << std::endl;
        return 1;
    }

    nNumberOfBytesToRead = GetFileSize(hFile, NULL);

    if (nNumberOfBytesToRead == INVALID_FILE_SIZE)
    {
        std::cerr << "Failed to read file size of " << pszFilePath << "." << std::endl;
        return 1;
    }

    lpFileContent = HeapAlloc(GetProcessHeap(), NULL, nNumberOfBytesToRead);

    if (lpFileContent == NULL)
    {
        std::cerr << "Failed to allocate memory on the Heap for file content." << std::endl;
        return 1;
    }

    if (ReadFile(hFile, lpFileContent, nNumberOfBytesToRead, &nNumberOfBytesRead, NULL) == FALSE)
    {
        std::cerr << "Failed to read file into memory." << std::endl;
        return 1;
    }

    if (nNumberOfBytesToRead != nNumberOfBytesRead)
    {
        std::cerr << "Expected to read " << nNumberOfBytesToRead << " bytes but only read " << nNumberOfBytesRead << " bytes." << std::endl;
        return 1;
    }
	std::cout << std::endl;
    std::cout << "File:" << '\t' << pszFilePath << std::endl;
    std::cout << "Size:" << '\t' << nNumberOfBytesRead << " bytes" << std::endl;

    piDosHeader = static_cast<PIMAGE_DOS_HEADER>(lpFileContent);

    if (piDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Not a PE file." << std::endl;
        return 1;
    }

	// DOS HEADER
	printf("\nDOS HEADER\n\n");
	printf("%-40s 0x%x\n", "Magic Number", piDosHeader->e_magic);
	printf("%-40s 0x%x\n", "Bytes on last page of file", piDosHeader->e_cblp);
	printf("%-40s 0x%x\n", "Pages in file", piDosHeader->e_cp);
	printf("%-40s 0x%x\n", "Relocations", piDosHeader->e_crlc);
	printf("%-40s 0x%x\n", "Size of header in paragraphs", piDosHeader->e_cparhdr);
	printf("%-40s 0x%x\n", "Minimum extra paragraphs needed", piDosHeader->e_minalloc);
	printf("%-40s 0x%x\n", "Maximum extra paragraphs needed", piDosHeader->e_maxalloc);
	printf("%-40s 0x%x\n", "Initial (relative) SS value", piDosHeader->e_ss);
	printf("%-40s 0x%x\n", "Initial SP value", piDosHeader->e_sp);
	printf("%-40s 0x%x\n", "Initial SP value", piDosHeader->e_sp);
	printf("%-40s 0x%x\n", "Checksum", piDosHeader->e_csum);
	printf("%-40s 0x%x\n", "Initial IP value", piDosHeader->e_ip);
	printf("%-40s 0x%x\n", "Initial (relative) CS value", piDosHeader->e_cs);
	printf("%-40s 0x%x\n", "File address of relocation table", piDosHeader->e_lfarlc);
	printf("%-40s 0x%x\n", "Overlay number", piDosHeader->e_ovno);
	printf("%-40s 0x%x\n", "OEM identifier (for e_oeminfo)", piDosHeader->e_oemid);
	printf("%-40s 0x%x\n", "OEM information; e_oemid specific", piDosHeader->e_oeminfo);
	printf("%-40s 0x%x\n", "File address of NT header", piDosHeader->e_lfanew);

	piNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((static_cast<PBYTE>(lpFileContent) + piDosHeader->e_lfanew));

	if (piNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "NT Header not valid." << std::endl;
		return 1;
	}

	// IMAGE_NT_HEADERS
	printf("\nNT HEADER\n\n");
	printf("%-40s 0x%x\n", "Signature", piNtHeaders->Signature);

	// FILE_HEADER
	printf("\nFILE HEADERS\n\n");
	printf("%-40s 0x%x\n", "Machine", piNtHeaders->FileHeader.Machine);
	printf("%-40s 0x%x\n", "Number of Sections", piNtHeaders->FileHeader.NumberOfSections);
	printf("%-40s 0x%x\n", "Time Stamp", piNtHeaders->FileHeader.TimeDateStamp);
	printf("%-40s 0x%x\n", "Pointer to Symbol Table", piNtHeaders->FileHeader.PointerToSymbolTable);
	printf("%-40s 0x%x\n", "Number of Symbols", piNtHeaders->FileHeader.NumberOfSymbols);
	printf("%-40s 0x%x\n", "Size of Optional Header", piNtHeaders->FileHeader.SizeOfOptionalHeader);
	printf("%-40s 0x%x\n", "Characteristics", piNtHeaders->FileHeader.Characteristics);

	// OPTIONAL_HEADER
	printf("\nOPTIONAL HEADERS\n\n");
	printf("%-40s 0x%x\n", "Magic number", piNtHeaders->OptionalHeader.Magic);
	printf("%-40s 0x%x\n", "Major Linker Version", piNtHeaders->OptionalHeader.MajorLinkerVersion);
	printf("%-40s 0x%x\n", "Minor Linker Version", piNtHeaders->OptionalHeader.MinorLinkerVersion);
	printf("%-40s 0x%x\n", "Size Of Code", piNtHeaders->OptionalHeader.SizeOfCode);
	printf("%-40s 0x%x\n", "Size Of Initialized Data", piNtHeaders->OptionalHeader.SizeOfInitializedData);
	printf("%-40s 0x%x\n", "Size Of UnInitialized Data", piNtHeaders->OptionalHeader.SizeOfUninitializedData);
	printf("%-40s 0x%x\n", "Address Of Entry Point (.text)", piNtHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("%-40s 0x%x\n", "Base Of Code", piNtHeaders->OptionalHeader.BaseOfCode);
	printf("%-40s 0x%Ix\n", "Image Base", piNtHeaders->OptionalHeader.ImageBase);
	printf("%-40s 0x%x\n", "Section Alignment", piNtHeaders->OptionalHeader.SectionAlignment);
	printf("%-40s 0x%x\n", "File Alignment", piNtHeaders->OptionalHeader.FileAlignment);
	printf("%-40s 0x%x\n", "Major Operating System Version", piNtHeaders->OptionalHeader.MajorOperatingSystemVersion);
	printf("%-40s 0x%x\n", "Minor Operating System Version", piNtHeaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("%-40s 0x%x\n", "Major Image Version", piNtHeaders->OptionalHeader.MajorImageVersion);
	printf("%-40s 0x%x\n", "Minor Image Version", piNtHeaders->OptionalHeader.MinorImageVersion);
	printf("%-40s 0x%x\n", "Major Subsystem Version", piNtHeaders->OptionalHeader.MajorSubsystemVersion);
	printf("%-40s 0x%x\n", "Minor Subsystem Version", piNtHeaders->OptionalHeader.MinorSubsystemVersion);
	printf("%-40s 0x%x\n", "Win32 Version Value", piNtHeaders->OptionalHeader.Win32VersionValue);
	printf("%-40s 0x%x\n", "Size Of Image", piNtHeaders->OptionalHeader.SizeOfImage);
	printf("%-40s 0x%x\n", "Size Of Headers", piNtHeaders->OptionalHeader.SizeOfHeaders);
	printf("%-40s 0x%x\n", "CheckSum", piNtHeaders->OptionalHeader.CheckSum);
	printf("%-40s 0x%x\n", "Subsystem", piNtHeaders->OptionalHeader.Subsystem);
	printf("%-40s 0x%x\n", "DllCharacteristics", piNtHeaders->OptionalHeader.DllCharacteristics);
	printf("%-40s 0x%Ix\n", "Size Of Stack Reserve", piNtHeaders->OptionalHeader.SizeOfStackReserve);
	printf("%-40s 0x%Ix\n", "Size Of Stack Commit", piNtHeaders->OptionalHeader.SizeOfStackCommit);
	printf("%-40s 0x%Ix\n", "Size Of Heap Reserve", piNtHeaders->OptionalHeader.SizeOfHeapReserve);
	printf("%-40s 0x%Ix\n", "Size Of Heap Commit", piNtHeaders->OptionalHeader.SizeOfHeapCommit);
	printf("%-40s 0x%x\n", "Loader Flags", piNtHeaders->OptionalHeader.LoaderFlags);
	printf("%-40s 0x%x\n", "Number Of Rva And Sizes", piNtHeaders->OptionalHeader.NumberOfRvaAndSizes);

	// DATA_DIRECTORIES
	printf("\nDATA DIRECTORIES\n\n");
	const char* rgDataDirectories[16] = { 
		"Export", "Import", "Resource", "Exception", 
		"Certificate", "Base Relocation", "Debug",  "Architecture", 
		"Global ptr", "TLS Table", "Load Config Table", "Bound Import", 
		"IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
	};

	for (DWORD i = 0; i < piNtHeaders->OptionalHeader.NumberOfRvaAndSizes; i++)
	{
		printf("%s Directory Address: 0x%x; Size: 0x%x\n", rgDataDirectories[i], piNtHeaders->OptionalHeader.DataDirectory[i].VirtualAddress, piNtHeaders->OptionalHeader.DataDirectory[i].Size);
	}

	// SECTIONS
	printf("\nSECTIONS\n\n");

	piSectionHeader = IMAGE_FIRST_SECTION(piNtHeaders);

	for (WORD i = 0; i < piNtHeaders->FileHeader.NumberOfSections; i++)
	{
		printf("\n%-40s %d: %s\n\n", "Section Number and Name", i, piSectionHeader->Name);
		printf("%-40s 0x%x\n", "Virtual Size", piSectionHeader->Misc.VirtualSize);
		printf("%-40s 0x%x\n", "Virtual Address", piSectionHeader->VirtualAddress);
		printf("%-40s 0x%x\n", "Size Of Raw Data", piSectionHeader->SizeOfRawData);
		printf("%-40s 0x%x\n", "Pointer To Raw Data", piSectionHeader->PointerToRawData);
		printf("%-40s 0x%x\n", "Pointer To Relocations", piSectionHeader->PointerToRelocations);
		printf("%-40s 0x%x\n", "Pointer To Line Numbers", piSectionHeader->PointerToLinenumbers);
		printf("%-40s 0x%x\n", "Number Of Relocations", piSectionHeader->NumberOfRelocations);
		printf("%-40s 0x%x\n", "Number Of Line Numbers", piSectionHeader->NumberOfLinenumbers);
		printf("%-40s 0x%x\n", "Characteristics", piSectionHeader->Characteristics);

		piSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((reinterpret_cast<PBYTE>(piSectionHeader) + sizeof(IMAGE_SECTION_HEADER)));
	}

    HeapFree(GetProcessHeap(), NULL, lpFileContent);
    CloseHandle(hFile);
    return 0;
}
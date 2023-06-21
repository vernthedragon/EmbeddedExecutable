
#include <iostream>
#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include "Exe.h"
typedef LONG(WINAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

#define RELOC_32BIT_FIELD 3
#define PEMAXOFFSET 1024

IMAGE_NT_HEADERS* GetNTHeaders(unsigned char* data);
bool ApplyRelocation(ULONG NewBase, ULONG OldBase, IMAGE_NT_HEADERS* NTHeaders, DWORD ModulePointer, DWORD ModuleSize);
bool FixImportAddressTable(unsigned char* ModulePointer, IMAGE_NT_HEADERS* NTHeaders);
IMAGE_DATA_DIRECTORY* GetRelocationData(IMAGE_NT_HEADERS* NTHeaders, int Directory);
int main()
{
	std::cout << "We will now start another executable from memory\n\n";

	NtUnmapViewOfSection_t NtUnmapViewOfSection;

	IMAGE_NT_HEADERS* NTHeaders = GetNTHeaders(Exe);
	if (NTHeaders == NULL) {
		return 0;
	}
	IMAGE_DATA_DIRECTORY* DataDirectory = GetRelocationData(NTHeaders, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	auto Addr = (LPVOID)NTHeaders->OptionalHeader.ImageBase;

	NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection");
	NtUnmapViewOfSection((HANDLE)-1, (LPVOID)NTHeaders->OptionalHeader.ImageBase);

	unsigned char* DLLBaseAddress = (unsigned char*)VirtualAlloc(Addr, NTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!DLLBaseAddress && !DataDirectory)
		return 0;

	if (!DLLBaseAddress && DataDirectory)
		DLLBaseAddress = (unsigned char*)VirtualAlloc(NULL, NTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	NTHeaders->OptionalHeader.ImageBase = (DWORD)DLLBaseAddress;
	memcpy(DLLBaseAddress, Exe, NTHeaders->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER* SecHeaderAddr = (IMAGE_SECTION_HEADER*)((unsigned int)(NTHeaders)+sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++)
		memcpy(LPVOID((unsigned int)(DLLBaseAddress)+SecHeaderAddr[i].VirtualAddress), LPVOID((unsigned int)(Exe)+SecHeaderAddr[i].PointerToRawData), SecHeaderAddr[i].SizeOfRawData);

	FixImportAddressTable(DLLBaseAddress, NTHeaders);
	if (DLLBaseAddress != Addr)
		ApplyRelocation((ULONG)DLLBaseAddress, (ULONG)Addr, NTHeaders, NTHeaders->OptionalHeader.ImageBase, NTHeaders->OptionalHeader.SizeOfImage);

	ULONG Entry = (ULONG)(DLLBaseAddress)+NTHeaders->OptionalHeader.AddressOfEntryPoint;


	((int(*)())Entry)();
}




IMAGE_NT_HEADERS* GetNTHeaders(unsigned char* data)
{
	if (data == NULL)
		return NULL;

	IMAGE_DOS_HEADER* Header = (IMAGE_DOS_HEADER*)data;
	if (Header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	long Offset = Header->e_lfanew;
	if (Offset > PEMAXOFFSET)
		return NULL;

	IMAGE_NT_HEADERS32* NTHeader = (IMAGE_NT_HEADERS32*)(data + Offset);
	if (NTHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return NTHeader;
}

IMAGE_DATA_DIRECTORY* GetRelocationData(IMAGE_NT_HEADERS* NTHeaders, int Directory)
{
	if (Directory >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		return NULL;

	if (NTHeaders == NULL)
		return NULL;


	IMAGE_DATA_DIRECTORY* DataDirectory = &(NTHeaders->OptionalHeader.DataDirectory[Directory]);
	if (DataDirectory->VirtualAddress == NULL) {
		return NULL;
	}
	return DataDirectory;
}
bool ApplyRelocation(ULONG NewBase, ULONG OldBase, IMAGE_NT_HEADERS* NTHeaders, DWORD ModulePointer, DWORD ModuleSize)
{
	IMAGE_DATA_DIRECTORY* BaseRelocationDir = GetRelocationData(NTHeaders, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (BaseRelocationDir == NULL)
		return false;

	DWORD MaxSize = BaseRelocationDir->Size;
	DWORD RelocationAddress = BaseRelocationDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* BaseRelocation = NULL;

	DWORD parsedSize = 0;
	for (; parsedSize < MaxSize; parsedSize += BaseRelocation->SizeOfBlock) {
		BaseRelocation = (IMAGE_BASE_RELOCATION*)(RelocationAddress + parsedSize + ModulePointer);
		if (BaseRelocation->VirtualAddress == NULL || BaseRelocation->SizeOfBlock == 0)
			break;


		BASE_RELOCATION_ENTRY* Entry = (BASE_RELOCATION_ENTRY*)(DWORD(BaseRelocation) + sizeof(IMAGE_BASE_RELOCATION));
		for (DWORD i = 0; i < (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY); i++) {

			DWORD BaseRelocation_field = BaseRelocation->VirtualAddress + Entry->Offset;
			if (Entry->Offset == NULL || Entry->Type == 0)
				break;
			if (Entry->Type != RELOC_32BIT_FIELD) {
				return false;
			}
			if (BaseRelocation->VirtualAddress + Entry->Offset >= ModuleSize) {
				return false;
			}

			DWORD* BaseRelocationAddress = (DWORD*)(DWORD(ModulePointer) + BaseRelocation_field);
			(*BaseRelocationAddress) = ((*BaseRelocationAddress) - OldBase + NewBase);
			Entry = (BASE_RELOCATION_ENTRY*)(DWORD(Entry) + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	return (parsedSize != 0);
}
bool FixImportAddressTable(unsigned char* ModulePointer, IMAGE_NT_HEADERS* NTHeaders)
{
	IMAGE_DATA_DIRECTORY* Imports = GetRelocationData(NTHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (Imports == NULL) return false;




	for (DWORD Size = 0; Size < Imports->Size; Size += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		IMAGE_IMPORT_DESCRIPTOR* Library = (IMAGE_IMPORT_DESCRIPTOR*)(Imports->VirtualAddress + Size + (ULONG_PTR)ModulePointer);

		if (Library->OriginalFirstThunk == NULL && Library->FirstThunk == NULL)
			break;

		char* Name = (LPSTR)((ULONGLONG)ModulePointer + Library->Name);

		DWORD FirstThunk = Library->FirstThunk;
		DWORD ThunkAddress = Library->OriginalFirstThunk;

		if (ThunkAddress == NULL)
			ThunkAddress = Library->FirstThunk;

		DWORD Field = 0;
		DWORD Offset = 0;
		while (true)
		{
			IMAGE_THUNK_DATA* Thunk = (IMAGE_THUNK_DATA*)(DWORD(ModulePointer) + Field + FirstThunk);
			IMAGE_THUNK_DATA* Original = (IMAGE_THUNK_DATA*)(DWORD(ModulePointer) + Offset + ThunkAddress);

			if (Original->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || Original->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				Thunk->u1.Function = (DWORD)GetProcAddress(LoadLibraryA(Name), (char*)(Original->u1.Ordinal & 0xFFFF));


			if (Thunk->u1.Function == NULL)
				break;

			if (Thunk->u1.Function == Original->u1.Function)
				Thunk->u1.Function = (DWORD)GetProcAddress(LoadLibraryA(Name), (LPSTR)(((PIMAGE_IMPORT_BY_NAME)(DWORD(ModulePointer) + Original->u1.AddressOfData))->Name));

			Field += sizeof(IMAGE_THUNK_DATA);
			Offset += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return true;
}


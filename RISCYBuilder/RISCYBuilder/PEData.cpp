#include "stdafx.h"
#include "PEData.h"
#include <algorithm>

PEData::PEData(IMAGE_DOS_HEADER *exe,size_t size)
{
	Init(exe, size);
}

PEData::PEData(std::wstring filePath)
{
	HANDLE hPE = CreateFile(filePath.c_str(), GENERIC_READ, NULL, NULL, OPEN_EXISTING, 0, 0);
	if (hPE == NULL)
		exit(-1);
	LARGE_INTEGER fileSize = { 0,0 };
	GetFileSizeEx(hPE, &fileSize);
	IMAGE_DOS_HEADER *hollowedImage = (IMAGE_DOS_HEADER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize.LowPart);
	ReadFile(hPE, (void*)hollowedImage, fileSize.LowPart, NULL, NULL);
	CloseHandle(hPE);

	Init(hollowedImage, fileSize.LowPart);
}

void PEData::Init(IMAGE_DOS_HEADER *exe, size_t size)
{
	this->exe.buff = (void*)exe;
	this->exe.size = size;
	this->I_ntHeader = (IMAGE_NT_HEADERS*)((int)exe + ((IMAGE_DOS_HEADER*)exe)->e_lfanew);
	this->I_fileHeader = (IMAGE_FILE_HEADER*)&I_ntHeader->FileHeader;
	this->I_optionalHeader = (IMAGE_OPTIONAL_HEADER*)&this->I_ntHeader->OptionalHeader;
	ExtractSections();
	ExtractImports();
}

DWORD PEData::Rva2Offset(DWORD dwRva)
{
	IMAGE_SECTION_HEADER *secHeader = IMAGE_FIRST_SECTION(this->I_ntHeader);

	for (USHORT i = 0; i < this->I_fileHeader->NumberOfSections; i++)
	{
		if (dwRva >= secHeader->VirtualAddress)
		{
			if (dwRva < secHeader->VirtualAddress + secHeader->Misc.VirtualSize)
				return (DWORD)(dwRva - secHeader->VirtualAddress + secHeader->PointerToRawData);
		}
		secHeader++;
	}
	return -1;
}

void PEData::ExtractSections()
{
	IMAGE_SECTION_HEADER *secHeader = IMAGE_FIRST_SECTION(this->I_ntHeader);

	for (int i = 0; i < this->I_fileHeader->NumberOfSections; i++) {
		si.push_back(SectionInfo((char*)secHeader->Name, secHeader->PointerToRawData, secHeader->VirtualAddress, secHeader->SizeOfRawData, secHeader->Misc.VirtualSize));
		secHeader++;
	}
}

void PEData::HollowOutExe(size_t size, int offset)
{
	size_t newSize= this->exe.size + size;
	this->exe.buff = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,this->exe.buff, newSize*2);
	this->exe.size = newSize;
    void* startOfCave = (void*)((int)this->exe.buff + offset);

	memmove((void*)((int)startOfCave + size), startOfCave, size);
	memset(startOfCave, 0, size);
}

void PEData::WriteResource(std::vector<BYTE> buff, size_t size, std::string resNameStr)
{
	wchar_t resourceName[MAX_PATH] = {};
	std::copy(resNameStr.begin(), resNameStr.end(), resourceName);

	void *rsrc = (void*)this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	int rsrcSize = this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;

	IMAGE_RESOURCE_DIRECTORY *resources = (PIMAGE_RESOURCE_DIRECTORY)((int)this->exe.buff+Rva2Offset((DWORD)rsrc));
	IMAGE_RESOURCE_DIRECTORY_ENTRY *listItem = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resources + 1);
	PIMAGE_RESOURCE_DIRECTORY_ENTRY resSection;
	PIMAGE_RESOURCE_DIRECTORY child;
	PIMAGE_RESOURCE_DATA_ENTRY data_entry;
	VS_VERSIONINFO *version_info;

	for (int i = 0; i < resources->NumberOfIdEntries; i++)
	{
		if (!listItem->NameIsString)
			continue;

		void* nameInfo = (void*)((DWORD)(listItem->Name & 0x7FFFFFFF) + (DWORD)resources);
		if (!lstrcmpW((wchar_t*)((int)nameInfo + sizeof(WORD)), resourceName)) {
			if (listItem->DataIsDirectory) {
				child = (PIMAGE_RESOURCE_DIRECTORY)((listItem->OffsetToData & 0x7FFFFFFF) + (DWORD)resources);
				resSection = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(child + 1);
				if (resSection->DataIsDirectory) {
					child = (PIMAGE_RESOURCE_DIRECTORY)((resSection->OffsetToData & 0x7FFFFFFF) + (DWORD)resources);
					resSection = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(child + 1);

					data_entry = (PIMAGE_RESOURCE_DATA_ENTRY)((resSection->OffsetToData & 0x7FFFFFFF) + (DWORD)resources);
					
					int dataOffset = Rva2Offset(data_entry->OffsetToData);
					memset((void*)((int)this->exe.buff+dataOffset), 0, data_entry->Size);
					data_entry->Size = size;
					HollowOutExe(size, dataOffset);
					memcpy((void*)((int)this->exe.buff + dataOffset), buff.data(), size);
				}
			}
			listItem += 1;
		}
	}
}

//sort function ordering by OFT
bool sortOFT(IMAGE_IMPORT_DESCRIPTOR* a, IMAGE_IMPORT_DESCRIPTOR* b)
{
	if (a->OriginalFirstThunk > b->OriginalFirstThunk)
		return false;
	return true;
}

void PEData::ExtractImports()
{

	IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)this->exe.buff + Rva2Offset(this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	std::vector<IMAGE_IMPORT_DESCRIPTOR*> thunkList;
	//Do not convert to raw address, we need loaded location
	this->iat.offset = this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;

	int importSize = (this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	//build in order import (needed for IAT)
	while (imports->Name != NULL)
	{
		thunkList.push_back(imports);
		imports++;
	}

	std::sort(thunkList.begin(), thunkList.end(), sortOFT);

	for (std::vector<IMAGE_IMPORT_DESCRIPTOR*>::iterator it = thunkList.begin(); it != thunkList.end(); ++it)
	{
		Thunk t;

		t.libname = std::string((char*)((DWORD)this->exe.buff + Rva2Offset((*it)->Name)));

		IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((int)this->exe.buff + Rva2Offset((*it)->OriginalFirstThunk));
		while (*(DWORD*)thunk != NULL) {

			t.functionNames.push_back((char*)((int)this->exe.buff + Rva2Offset(thunk->u1.Function + 2)));
			thunk++;
		}
		this->iat.thunks.push_back(t);
	}

}

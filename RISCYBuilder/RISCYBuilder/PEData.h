#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <map>

struct SectionInfo {
	SectionInfo(char name[], int ro, int vo, int rs, int vs) { memcpy(sectionName, name, strlen((char*)name)); _rOffset = ro; _vOffset = vo; _rSize = rs; _vSize = vs; }
	char sectionName[8] = {};
	int _rOffset, _vOffset, _rSize, _vSize;
};

struct Thunk {
	std::string libname;
	std::vector<std::string> functionNames;
};

struct IAT {
	unsigned int offset;
	std::vector<Thunk> thunks;
};

typedef struct tag_VS_VERSIONINFO
{
	USHORT wLength;         // 00 length of entire version resource
	USHORT wValueLength;    // 02 length of fixed file info, if any
	USHORT wType;           // 04 type of resource (1 = text, 0 = binary)
	WCHAR szKey[17];        // 06 key -- VS_VERSION_INFO + padding byte
	VS_FIXEDFILEINFO Value; // 28 fixed information about this file (13 dwords)
}
VS_VERSIONINFO, *PVS_VERSIONINFO;   // 5C

typedef struct EXE {
	void *buff;
	size_t size;
};

class PEData
{
public:
	PEData(IMAGE_DOS_HEADER* exe,size_t size);
	PEData(std::wstring filePath);
	void Init(IMAGE_DOS_HEADER *exe, size_t size);
	void WriteResource(std::vector<BYTE> buff, size_t size, std::string resNameStr);
	IAT GetIAT() { return iat; }
	std::vector<SectionInfo> GetSections() { return si; }
	IMAGE_OPTIONAL_HEADER *GetOptionalHeader() { return this->I_optionalHeader; }
	void *GetExeBuffer() { return this->exe.buff; }
	DWORD PEData::GetEntryPoint() { return this->I_optionalHeader->AddressOfEntryPoint; }
	size_t GetExeSize() { return this->exe.size; }

protected:
	IMAGE_OPTIONAL_HEADER *I_optionalHeader;
	void HollowOutExe(size_t size, int offset);
	IMAGE_NT_HEADERS *I_ntHeader;
	IMAGE_FILE_HEADER *I_fileHeader;
	IMAGE_DATA_DIRECTORY *I_dataDirectory;
	DWORD Rva2Offset(DWORD dwRva);
	void ExtractSections();
	void ExtractImports();
	std::vector<SectionInfo> si;
	IAT iat;
	EXE exe;
};

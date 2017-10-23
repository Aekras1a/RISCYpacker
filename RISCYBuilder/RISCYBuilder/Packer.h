#pragma once
#include <Windows.h>
#include <vector>
#include "PEData.h"
#include "Settings.h"

#define KEY_SIZE 32

//Base packer class. Packing can be packed in different areas
//in an executable (resource, section, append to file, etc)
//those specifics are defined in super class

class Packer
{
public:
	Packer(IMAGE_DOS_HEADER *exe, size_t fSize, Settings setting);
	bool virtual Pack() = 0;
	size_t DropPackedExe();
	std::wstring GetOutputExePath();

protected:
	void ZLIBcompress();
	void Crypt();
	std::vector<BYTE> packedBinary;
	PEData* packPEd;
	PEData *parentPEd;
	EXE packExe;
	EXE parentExe;
	Settings setting;

private:
	std::wstring outputExePath;
	BYTE key[KEY_SIZE];
	void GenKey(BYTE *key);
};


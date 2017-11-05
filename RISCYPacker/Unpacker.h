#pragma once
#include <string>
#include "Hollower.h"

class Unpacker
{
public:
	Unpacker();
	bool UnpackIntoProcess();
	~Unpacker();
private:
	BYTE *data;
	BYTE packLocation;
	std::wstring procPath;
	IMAGE_DOS_HEADER* exe;
	BYTE* Unpack();
};


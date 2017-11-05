#include "stdafx.h"
#include "Packer.h"
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <wincrypt.h>

#define EXE_OFFSET 0x200

Packer::Packer(IMAGE_DOS_HEADER *exe, size_t fSize, Settings setting)
{
	this->parentPEd = new PEData(exe, fSize);

	GenKey(this->key);

	HANDLE hPackExe = CreateFile(setting.exePath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
	LARGE_INTEGER packSize = { 0,0 };

	GetFileSizeEx(hPackExe, &packSize);
	BYTE* packBuff = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packSize.LowPart + EXE_OFFSET);
	*(BYTE*)packBuff = setting.packLocation;
	std::string ansiPath(setting.exePath.begin(), setting.exePath.end());
	memcpy(packBuff+2, ansiPath.c_str(), ansiPath.size());


	ReadFile(hPackExe, (void*)(packBuff + EXE_OFFSET), packSize.LowPart, NULL, NULL);
	this->packPEd = new PEData((IMAGE_DOS_HEADER*)(packBuff + EXE_OFFSET), packSize.LowPart);
	this->packData.buff = packBuff;
	this->packData.size = packSize.LowPart;

	std::wstring s = setting.exePath;
	std::wstring extention = s.substr(s.find_last_of(L".") + 1);
	s.erase(s.find_last_of(L"."), std::wstring::npos);
	this->outputExePath = s + L"-PACKED." + extention;
}

std::wstring Packer::GetOutputExePath()
{
	return this->outputExePath;
}

size_t Packer::DropPackedExe()
{
	DWORD written;

	HANDLE hPacked = CreateFile(outputExePath.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hPacked == INVALID_HANDLE_VALUE)
		return 0;
	WriteFile(hPacked, this->parentPEd->GetExeBuffer(), this->parentPEd->GetExeSize(), &written, NULL);
	CloseHandle(hPacked);
	return written;
}

void Packer::GenKey(BYTE *key)
{
	HCRYPTPROV hProv;
	CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(hProv, KEY_SIZE, key);
}

void Packer::Crypt()
{
	int i = 0;
	for (std::vector<BYTE>::iterator it = this->packedBinary.begin(); it != this->packedBinary.end(); ++it)
	{
		*it = *it^key[i % KEY_SIZE];
		i++;
	}

	return;
}

void Packer::ZLIBcompress()
{
	boost::iostreams::filtering_ostream os;
	const char* end = (char*)((int)this->packPEd->GetExeBuffer() + this->packData.size);
	const char* cExe = (char*)this->packData.buff;

	std::vector<BYTE> decompressed;
	decompressed.insert(decompressed.end(), cExe, end);
	std::vector<BYTE> compressed = std::vector<BYTE>();

	{
		boost::iostreams::filtering_ostream os;

		os.push(boost::iostreams::zlib_compressor());
		os.push(std::back_inserter(compressed));

		boost::iostreams::write(os, reinterpret_cast<const char*>(&decompressed[0]), decompressed.size());
	}

	this->packedBinary = compressed;
}

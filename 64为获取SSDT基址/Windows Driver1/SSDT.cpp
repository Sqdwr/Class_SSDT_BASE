#include "SSDT.h"

SSDT::SSDT()
{
	NtdllImageBase = NULL;
	ServiceTableBase = NULL;
	ShadowServiceTableBase = NULL;
}

SSDT::~SSDT()
{
	if (NtdllImageBase != NULL)
		ExFreePoolWithTag(NtdllImageBase, 'ytz');
}

BOOLEAN SSDT::FindSSDT()
{
	ULONG_PTR SystemCall64;								//��msr�ж�ȡ����SystemCall64�ĵ�ַ
	ULONG_PTR StartAddress;								//��Ѱ����ʼ��ַ����SystemCall64����ʼ��ַ
	ULONG_PTR EndAddress;								//��Ѱ���ս��ַ
	UCHAR *p;											//�����жϵ�������

	SystemCall64 = __readmsr(0xC0000082);
	StartAddress = SystemCall64;
	EndAddress = StartAddress + 0x500;
	while (StartAddress < EndAddress)
	{
		p = (UCHAR*)StartAddress;
		if (MmIsAddressValid(p) && MmIsAddressValid(p + 1) && MmIsAddressValid(p + 2))
		{
			if (*p == 0x4c && *(p + 1) == 0x8d && *(p + 2) == 0x15)
			{
				ServiceTableBase = (PSYSTEM_SERVICE_TABLE)(*(ULONG*)(p + 3) + (ULONG_PTR)(p + 7));
				ShadowServiceTableBase = (PSYSTEM_SERVICE_TABLE)(*(ULONG*)(p + 10) + (ULONG_PTR)(p + 14));
				break;
			}
		}
		++StartAddress;
	}

	if (ServiceTableBase == NULL)
	{
		KdPrint(("ServiceTableBase��ʼ��ʧ�ܣ�\n"));
		return FALSE;
	}

	KdPrint(("ServiceTableBase��ʼ���ɹ���\n"));
	return TRUE;
}

BOOLEAN SSDT::LoadNtdll()
{
	WCHAR NtdllPath[] = L"\\SystemRoot\\system32\\ntdll.dll";
	UNICODE_STRING FilePath = { 0 };
	IO_STATUS_BLOCK IoBlock = { 0 };
	OBJECT_ATTRIBUTES FileAttributes = { 0 };
	HANDLE FileHandle = NULL;

	CHAR *FileContent = NULL;
	LARGE_INTEGER ReadBytes = { 0 };
	FILE_STANDARD_INFORMATION FileInformation = { 0 };

	IMAGE_DOS_HEADER *DosHeader = NULL;
	IMAGE_NT_HEADERS *NtHeader = NULL;
	IMAGE_SECTION_HEADER * SectionHeader = NULL;
	IMAGE_BASE_RELOCATION * RelocationBase = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&FilePath, NtdllPath);
	InitializeObjectAttributes(&FileAttributes, &FilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

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
		KdPrint(("���ļ�ʧ�ܣ��������ǣ�%x\n", Status));
		return FALSE;
	}

	Status = ZwQueryInformationFile(FileHandle,
		&IoBlock,
		&FileInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);

		KdPrint(("��ȡ�ļ���Ϣʧ�ܣ��������ǣ�%x\n", Status));
		return FALSE;
	}

	if (FileInformation.EndOfFile.HighPart != 0 || FileInformation.EndOfFile.LowPart < sizeof(IMAGE_DOS_HEADER))
	{
		ZwClose(FileHandle);

		KdPrint(("�ļ���С����ȷ��"));
		return FALSE;
	}

	FileContent = (CHAR*)sfExAllocateMemory(FileInformation.EndOfFile.LowPart);
	if (FileContent == NULL)
	{
		ZwClose(FileHandle);

		KdPrint(("�����ڴ�%d�ֽ�ʧ�ܣ�", FileInformation.EndOfFile.LowPart));
		return FALSE;
	}

	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, FileInformation.EndOfFile.LowPart, &ReadBytes, NULL);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		sfFreeMemory(FileContent);

		KdPrint(("��ȡ�ļ�ʧ�ܣ��������ǣ�%x\n", Status));
		return FALSE;
	}

	DosHeader = (IMAGE_DOS_HEADER *)FileContent;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		ZwClose(FileHandle);
		sfFreeMemory(FileContent);

		KdPrint(("���ļ�����PE�ļ���\n"));
		return FALSE;
	}

	NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		ZwClose(FileHandle);
		sfFreeMemory(FileContent);

		KdPrint(("���ļ�����PE�ļ���\n"));
		return FALSE;
	}

	NtdllImageBase = (CHAR *)sfExAllocateMemory(NtHeader->OptionalHeader.SizeOfImage);
	if (NtdllImageBase == NULL)
	{
		ZwClose(FileHandle);
		sfFreeMemory(FileContent);

		KdPrint(("�����ڴ�%d�ֽ�ʧ�ܣ�", NtHeader->OptionalHeader.SizeOfImage));
		return FALSE;
	}

	RtlZeroMemory(NtdllImageBase, NtHeader->OptionalHeader.SizeOfImage);
	RtlCopyMemory(NtdllImageBase, FileContent, NtHeader->OptionalHeader.SizeOfHeaders);

	SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		RtlCopyMemory(NtdllImageBase + SectionHeader->VirtualAddress, FileContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);

	return TRUE;
}

ULONG SSDT::GetProcIndex(CHAR * ProcName)
{
	IMAGE_DOS_HEADER *DosHeader = NULL;
	IMAGE_NT_HEADERS *NtHeader = NULL;
	IMAGE_EXPORT_DIRECTORY *ExportDirectory = NULL;

	USHORT i = 0;
	USHORT *ExportOrdinalsArry = NULL;
	ULONG* ExportNameArry = NULL;
	ULONG *ExportAddressArry = NULL;

	ULONG FuncIndex = 0;
	CHAR *LocalProcName = NULL;

	LocalProcName = (CHAR *)sfExAllocateMemory(strlen(ProcName) + 1);
	if (LocalProcName == NULL)
	{
		KdPrint(("���䱣���ַ������ڴ�ʧ�ܣ�\n"));
		return FuncIndex;
	}

	RtlZeroMemory(LocalProcName, strlen(ProcName) + 1);
	RtlCopyMemory(LocalProcName, ProcName, strlen(ProcName));
	LocalProcName[0] = 'N';
	LocalProcName[1] = 't';

	if (NtdllImageBase == NULL)
	{
		sfFreeMemory(LocalProcName);

		KdPrint(("NtdllImageû�г�ʼ����\n"));
		return FuncIndex;
	}

	DosHeader = (IMAGE_DOS_HEADER *)NtdllImageBase;
	NtHeader = (IMAGE_NT_HEADERS *)(NtdllImageBase + DosHeader->e_lfanew);

	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
	{
		sfFreeMemory(LocalProcName);

		KdPrint(("������Ϊ�գ�\n"));
		return FuncIndex;
	}

	ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtdllImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	ExportOrdinalsArry = (USHORT *)(NtdllImageBase + ExportDirectory->AddressOfNameOrdinals);
	ExportNameArry = (ULONG *)(NtdllImageBase + ExportDirectory->AddressOfNames);
	ExportAddressArry = (ULONG *)(NtdllImageBase + ExportDirectory->AddressOfFunctions);

	for (i = 0; i < ExportDirectory->NumberOfFunctions; ++i)
	{
		if (strcmp(LocalProcName, (CHAR *)(NtdllImageBase + ExportNameArry[i])) == 0)
		{
			FuncIndex = *(ULONG *)(NtdllImageBase + ExportAddressArry[ExportOrdinalsArry[i]] + 4);
			KdPrint(("%s�ı���ǣ�%d\n", ProcName, FuncIndex));
			break;
		}
	}

	sfFreeMemory(LocalProcName);
	return FuncIndex;
}

ULONG_PTR SSDT::GetSSDTProcByIndex(ULONG Index)
{
	ULONG_PTR FuncAddress = 0;
	
	if (ServiceTableBase == NULL)
	{
		KdPrint(("ServiceTableBase��ʼ��ʧ�ܣ�\n"));
		return 0;
	}

	FuncAddress = (ULONG_PTR)(ServiceTableBase->ServiceTableBase[Index] >> 4) + (ULONG_PTR)ServiceTableBase->ServiceTableBase;
	return FuncAddress;
}

ULONG_PTR SSDT::GetSSDTProcByName(CHAR * ProcName)
{
	ULONG FuncIndex = 0;

	FuncIndex = GetProcIndex(ProcName);
	if (FuncIndex == 0)
	{
		KdPrint(("û�ҵ�����%s��\n", ProcName));
		return 0;
	}

	return GetSSDTProcByIndex(FuncIndex);
}

ULONG_PTR SSDT::GetSSDTNumbers()
{
	if (ServiceTableBase == NULL)
	{
		KdPrint(("ServiceTableBase��ʼ��ʧ�ܣ�\n"));
		return 0;
	}

	return ServiceTableBase->NumberOfServices;
}
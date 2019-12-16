#pragma once
#ifndef _SSDT_H_
#define _SSDT_H_

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define sfAllocateMemory(SIZE) ExAllocatePoolWithTag(PagedPool,SIZE,'ttt')
#define sfFreeMemory(P) if(P){ExFreePoolWithTag(P,'ttt');P = NULL;}

#define SSDT_PRINT					L"CLASS_SSDT"

typedef struct _SYSTEM_SERVICE_TABLE
{
	PLONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	UINT64 NumberOfServices;
	PUCHAR ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	ULONG_PTR MappedBase;
	ULONG_PTR Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG ModuleNumber;
	SYSTEM_MODULE_INFORMATION_ENTRY ModuleEntry[1];					//�����ʵ��һ�����飬ֻ�ǳ����޷�ȷ��
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(IN ULONG SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);

class SSDT
{
public:
	SSDT();
	~SSDT();
	VOID GetKernelBase();																	// ��ȡNtoskrnl�Ļ�ַ
	VOID FindSSDT();																		// �ҵ�SSDT��λ��
	VOID LoadNtdll();																		// ����Ntdll
	ULONG GetProcIndex(CHAR *ProcName);														// ͨ����������ȡ����������SSDT�е��±�
	ULONG_PTR GetSSDTProcByIndex(ULONG Index);												// ͨ���±��ȡ������ַ
	ULONG_PTR GetSSDTProcByName(CHAR *ProcName);											// ͨ���������ֻ�ȡ������ַ
	ULONG_PTR GetSSDTNumbers();																// ��ȡSSDT���к����ĸ���
private:
	PSYSTEM_SERVICE_TABLE ServiceTableBase;
	PSYSTEM_SERVICE_TABLE ShadowServiceTableBase;
	
	PVOID NtoskrnlBase;
	ULONG NtoskrnlSize;

	CHAR *NtdllImageBase;
	IMAGE_EXPORT_DIRECTORY *ExportDirectory;
	USHORT *ExportOrdinalsArry;
	ULONG* ExportNameArry;
	ULONG *ExportAddressArry;
};

#endif
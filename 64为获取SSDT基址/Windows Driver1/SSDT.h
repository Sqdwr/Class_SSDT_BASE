#pragma once
#ifndef _SSDT_H_
#define _SSDT_H_

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define sfExAllocateMemory(SIZE) ExAllocatePoolWithTag(PagedPool,SIZE,'ytz')
#define sfFreeMemory(P) if(P){ExFreePoolWithTag(P,'ytz');P = NULL;}

EXTERN_C unsigned __int64 __readmsr(int register);				//读取msr寄存器
EXTERN_C unsigned __int64 __readcr0(void);						//读取cr0的值
EXTERN_C void __writecr0(unsigned __int64 Data);					//写入cr0的值

typedef struct _SYSTEM_SERVICE_TABLE
{
	PLONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	UINT64 NumberOfServices;
	PUCHAR ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

class SSDT
{
public:
	SSDT();
	~SSDT();
	BOOLEAN FindSSDT();
	BOOLEAN LoadNtdll();
	ULONG GetProcIndex(CHAR *ProcName);
	ULONG_PTR GetSSDTProcByIndex(ULONG Index);
	ULONG_PTR GetSSDTProcByName(CHAR *ProcName);
	ULONG_PTR GetSSDTNumbers();
private:
	PSYSTEM_SERVICE_TABLE ServiceTableBase;
	PSYSTEM_SERVICE_TABLE ShadowServiceTableBase;
	CHAR *NtdllImageBase;
};

#endif
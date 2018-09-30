#include "SSDT.h"

extern "C" VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	ULONG Index;
	SSDT Ssdt;
	for (Index = 0; Index < Ssdt.GetSSDTNumbers(); ++Index)
		KdPrint(("��%d��������ַ�ǣ�%llx\n", Index, Ssdt.GetSSDTProcByIndex(Index)));

	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
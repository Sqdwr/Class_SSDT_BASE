#include "SSDT.h"

extern "C" VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	SSDT Ssdt;

	__debugbreak();

	KdPrint(("NtOpenProcess:%llx!\n", Ssdt.GetSSDTProcByName("NtOpenProcess")));

	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
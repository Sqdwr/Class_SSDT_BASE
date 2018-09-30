#include "SSDT.h"

SSDT::SSDT()
{
	ULONG_PTR SystemCall64;								//从msr中读取到的SystemCall64的地址
	ULONG_PTR StartAddress;								//搜寻的起始地址就是SystemCall64的起始地址
	ULONG_PTR EndAddress;								//搜寻的终结地址
	UCHAR *p;											//用来判断的特征码

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
}

ULONG_PTR SSDT::GetSSDTProcByIndex(ULONG Index)
{
	ULONG_PTR FuncAddress = 0;
	FuncAddress = (ULONG_PTR)(ServiceTableBase->ServiceTableBase[Index] >> 4) + (ULONG_PTR)ServiceTableBase->ServiceTableBase;
	return FuncAddress;
}

ULONG_PTR SSDT::GetSSDTNumbers()
{
	return ServiceTableBase->NumberOfServices;
}
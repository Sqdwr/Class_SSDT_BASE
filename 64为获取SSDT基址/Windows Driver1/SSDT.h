#include <ntddk.h>

extern "C" unsigned __int64 __readmsr(int register);				//读取msr寄存器
extern "C" unsigned __int64 __readcr0(void);						//读取cr0的值
extern "C" void __writecr0(unsigned __int64 Data);					//写入cr0的值

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
	ULONG_PTR GetSSDTProcByIndex(ULONG Index);
	ULONG_PTR GetSSDTNumbers();
private:
	PSYSTEM_SERVICE_TABLE ServiceTableBase;
	PSYSTEM_SERVICE_TABLE ShadowServiceTableBase;
};
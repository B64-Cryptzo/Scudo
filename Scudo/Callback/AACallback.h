#pragma once
#include <Windows.h>

typedef enum _CPROCESSINFOCLASS {
    ProcessInstrumentationCallback = 40
} CPROCESSINFOCLASS;

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
	HANDLE ProcessHandle,
    CPROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX // Size=28
{
	PVOID Object; // Size=4 Offset=0
	ULONG UniqueProcessId; // Size=4 Offset=4
	ULONG HandleValue; // Size=4 Offset=8
	ULONG GrantedAccess; // Size=4 Offset=12
	USHORT CreatorBackTraceIndex; // Size=2 Offset=16
	USHORT ObjectTypeIndex; // Size=2 Offset=18
	ULONG HandleAttributes; // Size=4 Offset=20
	ULONG Reserved; // Size=4 Offset=24
};

struct SYSTEM_HANDLE_INFORMATION_EX // Size=36
{
	ULONG NumberOfHandles; // Size=4 Offset=0
	ULONG Reserved; // Size=4 Offset=4
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1]; // Size=36 Offset=8
};

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

extern bool InstallCallback(bool installCallback);
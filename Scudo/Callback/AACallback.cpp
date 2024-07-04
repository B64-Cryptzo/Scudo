#include <stdio.h>
#include "AACallback.h"

#include <A64XorStr.h>
#include <A64LazyImporter.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

EXTERN_C VOID instrument(void);

EXTERN_C LPVOID KiUserExceptionDispatcher = NULL;


bool InstallCallback(bool installCallback) {
    
    HMODULE hntdll = ShadowCall<HMODULE>(shadow::hash_t(x_("LoadLibraryA")), x_("ntdll.dll"));
    if (hntdll == NULL)
    {
        return false;
    }

    KiUserExceptionDispatcher = GetProcAddress(hntdll, x_("KiUserExceptionDispatcher"));
    if (KiUserExceptionDispatcher == NULL)
    {
        return false;
    }

    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(hntdll, x_("NtSetInformationProcess"));
    if (NtSetInformationProcess == NULL)
    {
        return false;
    }

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION processCallbackInformation;
    processCallbackInformation.Callback = installCallback ? instrument : nullptr;
    processCallbackInformation.Reserved = 0; // always 0
    processCallbackInformation.Version = 0;  // 0 for x64, 1 for x86

    if (!NT_SUCCESS(NtSetInformationProcess(
        (HANDLE)-1,
        ProcessInstrumentationCallback,
        &processCallbackInformation,
        sizeof(processCallbackInformation))))
    {
        return false;
    }
    return true;
}
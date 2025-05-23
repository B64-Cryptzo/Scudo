#pragma once
#include <windows.h>
#include <random>
#include <unordered_map>
#include <mutex>
#include <A64LazyImporter.h>

#define RVA(addAddress) (addAddress + (*reinterpret_cast<DWORD*>((uintptr_t)addAddress + 1)) + 5)

// Memory protection typedefs
using VirtualProtectFunc = BOOL(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

// MemoryProtect class to temporarily modify memory protection
class MemoryProtect
{
public:
    MemoryProtect(LPVOID address, SIZE_T size, DWORD newProtection)
        : address_(address), size_(size), oldProtection_(0), success_(false)
    {
        VirtualProtectFunc virtualProtectFunc = GetVirtualProtectFunc();
        if (virtualProtectFunc != nullptr)
        {
            success_ = virtualProtectFunc(address, size, newProtection, &oldProtection_);
        }
    }

    ~MemoryProtect()
    {
        if (success_)
        {
            VirtualProtectFunc virtualProtectFunc = GetVirtualProtectFunc();
            if (virtualProtectFunc != nullptr)
            {
                virtualProtectFunc(address_, size_, oldProtection_, &oldProtection_);
            }
        }
    }
    operator bool() const
    {
        return success_;
    }

private:
    LPVOID address_;
    SIZE_T size_;
    DWORD oldProtection_;
    bool success_;

    VirtualProtectFunc GetVirtualProtectFunc()
    {
        static VirtualProtectFunc virtualProtectFunc = reinterpret_cast<VirtualProtectFunc>(
            ShadowCall<FARPROC>("GetProcAddress", ShadowCall<HMODULE>("LoadLibraryA", "kernel32.dll"), "VirtualProtect")
            );

        return virtualProtectFunc;
    }
};
#pragma once
#include <Windows.h>
#include <vector>
#include <thread>

#include "../B64/B64Protect.h"


constexpr BYTE DEBUG_BYTE = 0xCC; // Intel ICE debugging byte


class Scudo {

    // Encrypt the function using B64 encryption
    std::vector<BYTE> EncryptFunction(void* function, SIZE_T size) {

        BYTE* functionBytes = static_cast<BYTE*>(function);
        std::vector<BYTE> encryptedBytes;

        // Skip the first byte and encrypt the rest
        for (SIZE_T i = 1; i < size; ++i) {
            BYTE encryptedByte = functionBytes[i] ^ xorKey; // Encrypt using XOR
            encryptedBytes.push_back(encryptedByte);
            functionBytes[i] = encryptedByte;
        }
        return encryptedBytes;
    }

    // Decrypt the function by XORing with debug byte
    void DecryptFunction(void* function, SIZE_T size) {

        MemoryProtect memFunction = MemoryProtect(function, size, PAGE_EXECUTE_READWRITE);

        *static_cast<BYTE*>(function) = this->firstByte;


        BYTE* functionBytes = static_cast<BYTE*>(function);
        for (SIZE_T i = 1; i < size; ++i) {
            functionBytes[i] ^= xorKey; // Decrypt using XOR
        }

        encryptedFunction.clear();

        wasDecrypted = true;
    }

public:
    using EncryptedFunctionMap = std::map<void*, Scudo*>;

    Scudo(void* functionAddress, SIZE_T functionSize) : functionAddress(functionAddress), functionSize(functionSize) {


        //Ensure valid function pointer was passed
        if (!functionAddress) 
            return;

        //Set the XOR byte to a random value
        std::srand(std::time(nullptr));
        xorKey = static_cast<unsigned int>(1000000000 + (std::rand() % (9999999999 - 1000000000 + 1)));

        if (!isExceptionHandlingInitialized) {
            exceptionHandler = AddVectoredExceptionHandler(0, ExceptionHandler);
            isExceptionHandlingInitialized = true;
        }

        //Set the protection
        MemoryProtect memFunction = MemoryProtect(functionAddress, functionSize, PAGE_EXECUTE_READWRITE);

        // Encrypt the function
        encryptedFunction = EncryptFunction(functionAddress, functionSize);

        // Save the first byte of the function
        firstByte = *static_cast<BYTE*>(functionAddress);
        encryptedFunction.insert(encryptedFunction.begin(), firstByte);

        // Set the first byte to the debug byte
        *static_cast<BYTE*>(functionAddress) = DEBUG_BYTE;

        // Store the encrypted function in the map
        encryptedFunctions[functionAddress] = this;

        functionEncrypted = true;

        std::thread enforcerThread([this]() {
            this->encryptionEnforcer();
            });
        enforcerThread.detach();
    }

    ~Scudo() {

        //Set the protection
        MemoryProtect memFunction = MemoryProtect(functionAddress, functionSize, PAGE_EXECUTE_READWRITE);

        // Restore the original function
        *static_cast<BYTE*>(functionAddress) = encryptedFunction[0];

        // Decrypt the function
        DecryptFunction(functionAddress, functionSize);

        functionEncrypted = false;


        // Clear the encrypted function vector and delete the objects
        encryptedFunction.clear();

        // Remove the encrypted function from the map
        encryptedFunctions.erase(functionAddress);

        if (isExceptionHandlingInitialized) {
            RemoveVectoredExceptionHandler(exceptionHandler);
            isExceptionHandlingInitialized = false;
        }
    }
    void encryptionEnforcer()
    {
        while (functionEncrypted)
        {
            if (wasDecrypted)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // TODO: find better way of waiting for function to finish executing

                //Ensure memory protection
                MemoryProtect memFunction = MemoryProtect(functionAddress, functionSize, PAGE_EXECUTE_READWRITE);

                // Encrypt the function
                encryptedFunction = EncryptFunction(functionAddress, functionSize);

                // Save the first byte of the function
                firstByte = *static_cast<BYTE*>(functionAddress);
                encryptedFunction.insert(encryptedFunction.begin(), firstByte);

                // Set the first byte to the debug byte
                *static_cast<BYTE*>(functionAddress) = DEBUG_BYTE;

                wasDecrypted = false; // Reset the decrypted flag
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    static bool IsEncryptedFunction(void* functionAddress) {
        return encryptedFunctions.find(functionAddress) != encryptedFunctions.end();
    }

    static Scudo* GetEncryptedFunction(void* functionAddress) {
        auto it = encryptedFunctions.find(functionAddress);
        if (it != encryptedFunctions.end()) {
            return it->second;
        }
        return nullptr;
    }

    static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {
        PEXCEPTION_RECORD exceptionRecord = exceptionInfo->ExceptionRecord;
        void* exceptionAddress = exceptionRecord->ExceptionAddress;


        if (exceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT && IsEncryptedFunction(exceptionAddress)) {

            currentEncryptedFunction = GetEncryptedFunction(exceptionAddress);

            if (currentEncryptedFunction) {

                // Decrypt the function
                currentEncryptedFunction->DecryptFunction(currentEncryptedFunction->functionAddress, currentEncryptedFunction->functionSize);

                // Resume execution
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // Continue searching for another exception handler
        return EXCEPTION_CONTINUE_SEARCH;
    }
    static EncryptedFunctionMap encryptedFunctions;
private:
    static thread_local Scudo* currentEncryptedFunction;
    void* functionAddress;
    SIZE_T functionSize;
    BYTE firstByte;
    unsigned int xorKey;
    std::vector<BYTE> encryptedFunction;
    PVOID exceptionHandler;
    bool functionEncrypted, wasDecrypted, isExceptionHandlingInitialized;
};

// Initialize static variables
typename Scudo::EncryptedFunctionMap Scudo::encryptedFunctions;

thread_local Scudo* Scudo::currentEncryptedFunction;
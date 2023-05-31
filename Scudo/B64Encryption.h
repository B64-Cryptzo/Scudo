#pragma once
#include <Windows.h>
#include <vector>
#include <thread>

#include "../B64/B64Protect.h"


constexpr BYTE DEBUG_BYTE = 0xCC; // Intel ICE debugging byte


class Scudo {

    /*
    * Encrypt the function using B64 encryption
    */
    void EncryptFunction(void* function, SIZE_T size) {

        // Set the protection
        MemoryProtect memFunction = MemoryProtect(functionAddress, functionSize, PAGE_EXECUTE_READWRITE);

        // Cast the address to an accessible BYTE pointer
        BYTE* functionBytes = static_cast<BYTE*>(function);

        // Save the first byte for the function
        this->firstByte = *functionBytes;

        // Skip the first byte and encrypt the rest
        for (SIZE_T i = 1; i < size; ++i) {
            functionBytes[i] ^= this->xorKey; // Encrypt using XOR
        }

        // Set the first byte to the debug byte
        *static_cast<BYTE*>(functionAddress) = DEBUG_BYTE;
    }
    /*
    * Decrypt the function by XORing with debug byte
    */
    void DecryptFunction(void* function, SIZE_T size) {

        // Set the protection
        MemoryProtect memFunction = MemoryProtect(function, size, PAGE_EXECUTE_READWRITE);

        // Cast the address to an accessible BYTE pointer
        BYTE* functionBytes = static_cast<BYTE*>(function);

        // Restore the first byte of the function
        *functionBytes = this->firstByte;

        for (SIZE_T i = 1; i < size; ++i) {
            functionBytes[i] ^= this->xorKey; // Decrypt using XOR
        }

        // Notify the enforcer thread to re-encrypt the function
        wasDecrypted = true;
    }

public:
    using EncryptedFunctionMap = std::map<void*, Scudo*>; // Map to access al encrypted functions

    /*
    * Initializer for Scudo that encrypts the function and ensures all variables are set for decryption
    */
    Scudo(void* functionAddress, SIZE_T functionSize) : functionAddress(functionAddress), functionSize(functionSize) {


        // Ensure valid function pointer was passed
        if (!functionAddress) 
            return;

        // Set the XOR byte to a random value
        std::srand(std::time(nullptr));
        xorKey = static_cast<unsigned int>(1000000000 + (std::rand() % (9999999999 - 1000000000 + 1)));

        // Initialize the Handler
        if (!isExceptionHandlingInitialized) {
            exceptionHandler = AddVectoredExceptionHandler(0, ExceptionHandler);
            isExceptionHandlingInitialized = true;
        }

        // Encrypt the function
        EncryptFunction(functionAddress, functionSize);

        // Store the encrypted function in the map
        encryptedFunctions[functionAddress] = this;

        // Set the encryption flag
        functionEncrypted = true;

        // Start a detached thread to check for decryptions
        std::thread enforcerThread([this]() {
            this->encryptionEnforcer();
            });
        enforcerThread.detach();
    }

    /*
    * Destructor for Scudo that decrypts the function and ensures all vectors and maps are adjusted
    */
    ~Scudo() {

        // Decrypt the function
        DecryptFunction(functionAddress, functionSize);

        // Alert Enforcer Thread
        functionEncrypted = false;

        // Remove the encrypted function from the map
        encryptedFunctions.erase(functionAddress);
    }

    /*
    * Thread that will re-encrypt functions after they have been decrypted
    */
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
                EncryptFunction(functionAddress, functionSize);

                // Set the first byte to the debug byte
                *static_cast<BYTE*>(functionAddress) = DEBUG_BYTE;

                wasDecrypted = false; // Reset the decrypted flag
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    /*
    * Returns true of the address passed is the entrypoint to an already encrypted function
    */
    static bool IsEncryptedFunction(void* functionAddress) {
        return encryptedFunctions.find(functionAddress) != encryptedFunctions.end();
    }

    /*
    * Returns class object of the function encrypted at the passed address
    */
    static Scudo* GetEncryptedFunction(void* functionAddress) {
        auto it = encryptedFunctions.find(functionAddress);
        if (it != encryptedFunctions.end()) {
            return it->second;
        }
        return nullptr;
    }
    
    /*
    * Exception handler that will handler and parse the ICE debug instructions placed on functions
    */
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
    PVOID exceptionHandler;
    bool functionEncrypted, wasDecrypted, isExceptionHandlingInitialized;
};

// Initialize static variables
typename Scudo::EncryptedFunctionMap Scudo::encryptedFunctions;

thread_local Scudo* Scudo::currentEncryptedFunction;
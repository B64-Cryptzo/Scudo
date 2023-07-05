#pragma once
#include "../B64/B64Protect.h"
#include "../B64/B64Function.h"

constexpr BYTE DEBUG_BYTE = 0xCC; // Intel ICE debugging byte

bool isExceptionHandlingInitialized = false;

class Scudo {

public:
    using EncryptedFunctionMap = std::map<void*, Scudo*>; // Map to access all encrypted functions

    /*
    * Initializer for Scudo that encrypts the function and ensures all variables are set for decryption
    */
    Scudo(void* functionAddress) : functionAddress(functionAddress), functionSize(GetFunctionLength(functionAddress)) {
        
        // Ensure valid function pointer was passed
        if (!functionAddress || !functionSize)
            return;

        // Set the XOR byte to a random value
        xorKey = std::random_device()() % 9000000000 + 1000000000;

        // Initialize the Handler
        if (!isExceptionHandlingInitialized) {
            exceptionHandler = AddVectoredExceptionHandler(0, ExceptionHandler);
            isExceptionHandlingInitialized = true;
        }

        // Encrypt the function
        encryptFunction(functionAddress, functionSize);

        // Store the encrypted function in the map
        encryptedFunctions[functionAddress] = this;
    }

    /*
    * Destructor for Scudo that decrypts the function and ensures all vectors and maps are adjusted
    */
    ~Scudo() {

        // Decrypt the function
        decryptFunction(functionAddress, functionSize);

        // Remove the encrypted function from the map
        encryptedFunctions.erase(functionAddress);
    }

private:
    /*
    * Exception handler that will handle and parse the ICE debug instructions placed on functions
    */
    static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {

        // Shorten the pointer chain for simplicity
        PEXCEPTION_RECORD exceptionRecord = exceptionInfo->ExceptionRecord;

        // If the exception isn't a breakpoint, look for another handler
        if (exceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
            return EXCEPTION_CONTINUE_SEARCH;

        // Get the address where the exception occured
        void* exceptionAddress = exceptionRecord->ExceptionAddress;

        /*
        * Use INT3 instruction breakpoint at return address found on the stack to trigger an exception which will
        * allow the program to re-encrypt the function immediately after it's done executing.
        */
        if (!isEncryptedFunction(exceptionAddress)) // Check if the breakpoint occured at an encrypted function
        {
            // Get the encrypted function's object from the return address associated with it
            if ((currentEncryptedFunction = returnAddressToFunction(exceptionAddress)), currentEncryptedFunction == nullptr)
                return EXCEPTION_CONTINUE_SEARCH;

            // Re-encrypt the function aswell as remove the breakpoint from the return address
            currentEncryptedFunction->encryptionRoutine();

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Get the encrypted function's object
        if ((currentEncryptedFunction = getEncryptedFunction(exceptionAddress)), currentEncryptedFunction == nullptr)
            return EXCEPTION_CONTINUE_SEARCH;

        PCONTEXT contextRecord = exceptionInfo->ContextRecord;

        // Create a pointer to the rspAddress
        uintptr_t* returnAddressPtr = reinterpret_cast<uintptr_t*>(contextRecord->Rsp);

        // Dereference the pointer to retrieve the return address value
        currentEncryptedFunction->lastReturnAddress = *returnAddressPtr;

        // Decrypts the function and puts breakpoint on return address
        currentEncryptedFunction->decryptionRoutine();

        // Resume execution
        return EXCEPTION_CONTINUE_EXECUTION;
        
    }

    /*
    * Returns true of the address passed is the entrypoint to an already encrypted function
    */
    static bool isEncryptedFunction(void* functionAddress) {
        return encryptedFunctions.find(functionAddress) != encryptedFunctions.end();
    }

    /*
    * Returns class object of the function encrypted at the passed address
    */
    static Scudo* getEncryptedFunction(void* functionAddress) {
        auto it = encryptedFunctions.find(functionAddress);
        if (it != encryptedFunctions.end()) {
            return it->second;
        }
        return nullptr;
    }

    /*
    * Returns the class object of the function encrypted with the specified return address
    */
    static Scudo* returnAddressToFunction(void* returnAddress) {
        for (const auto& pair : encryptedFunctions) {
            Scudo* encryptedFunction = pair.second;
            if (encryptedFunction->lastReturnAddress == reinterpret_cast<uintptr_t>(returnAddress)) {
                return encryptedFunction;
            }
        }
        return nullptr;
    }

    /*
    * Encrypt the function using B64 encryption
    */
    void encryptFunction(void* function, SIZE_T size) {

        // Set the protection
        MemoryProtect memFunction = MemoryProtect(functionAddress, functionSize, PAGE_EXECUTE_READWRITE);

        // Save the first byte for the function
        this->firstByte = *static_cast<BYTE*>(function);

        // Skip the first byte and encrypt the rest
        for (SIZE_T i = 1; i < size; ++i) {
            static_cast<BYTE*>(function)[i] ^= this->xorKey; // Encrypt using XOR
        }

        // Set the first byte to the debug byte
        *static_cast<BYTE*>(functionAddress) = DEBUG_BYTE;
    }

    /*
    * Decrypt the function by XORing with debug byte
    */
    void decryptFunction(void* function, SIZE_T size) {

        // Set the protection
        MemoryProtect memFunction = MemoryProtect(function, size, PAGE_EXECUTE_READWRITE);

        // Restore the first byte of the function
        *static_cast<BYTE*>(function) = this->firstByte;

        for (SIZE_T i = 1; i < size; ++i) {
            static_cast<BYTE*>(function)[i] ^= this->xorKey; // Decrypt using XOR
        }
    }

    /*
    * Routine for the handler to re-encrypt the function immediately after it finishes executing
    */
    void encryptionRoutine()
    {
        // Set the protection
        MemoryProtect memFunction = MemoryProtect((PVOID)currentEncryptedFunction->lastReturnAddress, sizeof(BYTE), PAGE_EXECUTE_READWRITE);

        // Reset the return address to normal
        *static_cast<BYTE*>((void*)this->lastReturnAddress) = this->lastReturnAddressByte;

        // Re-Encrypt the function
        this->encryptFunction(this->functionAddress, this->functionSize);
    }

    /*
    * Routine for the handler to dencrypt the function immediately after being called
    */
    void decryptionRoutine()
    {
        // Set the protection
        MemoryProtect memFunction = MemoryProtect((PVOID)currentEncryptedFunction->lastReturnAddress, sizeof(BYTE), PAGE_EXECUTE_READWRITE);

        // Save instruction at return address
        currentEncryptedFunction->lastReturnAddressByte = *reinterpret_cast<BYTE*>(currentEncryptedFunction->lastReturnAddress);

        // Place illegal instruction at return address
        *reinterpret_cast<BYTE*>(currentEncryptedFunction->lastReturnAddress) = DEBUG_BYTE;

        // Decrypt the function
        currentEncryptedFunction->decryptFunction(currentEncryptedFunction->functionAddress, currentEncryptedFunction->functionSize);
    }

    // For encryption and decryption
    void* functionAddress;
    SIZE_T functionSize;

    // For decryption
    BYTE firstByte;
    PVOID exceptionHandler;

    // For Encryption
    unsigned int xorKey;
    uintptr_t lastReturnAddress;
    BYTE lastReturnAddressByte;

    // For Handler
    static thread_local Scudo* currentEncryptedFunction;
    static EncryptedFunctionMap encryptedFunctions;
};

// Initialize static variables
typename Scudo::EncryptedFunctionMap Scudo::encryptedFunctions;

thread_local Scudo* Scudo::currentEncryptedFunction;

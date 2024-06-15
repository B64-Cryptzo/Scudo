#include "B64Encryption.h"

// Initialize static variables
thread_local Scudo* Scudo::currentEncryptedFunction; // A pointer to the currently selected EncryptedFunction

typename Scudo::EncryptedFunctionMap Scudo::encryptedFunctions; // A map of all our encrypted functions

std::atomic<bool> Scudo::isExceptionHandlingInitialized(false); // An atomic bool to determine if the exception handler is already initialized

std::mutex Scudo::encryptedFunctionsMutex; // A mutex to ensure thread safety

std::vector<std::unique_ptr<Scudo>> Scudo::protectedFunctions{};

PVOID Scudo::exceptionHandler = NULL;

void A64PROTECT(void* functionAddress) {
    Scudo::protectedFunctions.push_back(std::make_unique<Scudo>(functionAddress));
}

void A64UNPROTECT() {
    Scudo::UnprotectAll();
}

Scudo::Scudo(void* functionAddress)
    : functionAddress(functionAddress), functionSize(GetFunctionLength(functionAddress)) {

    // Ensure valid function pointer was passed
    if (!functionAddress || !functionSize)
        throw std::invalid_argument("Invalid functionAddress or functionSize");

    // Set the XOR byte to a random value (TODO - Encrypt with a 3 sequencial xor operations with 3 xor keys)
    xorKey = randomKey();

    // Check if the handler has already been initialized
    if (!isExceptionHandlingInitialized.load()) {

        // Install our exception handler
        exceptionHandler = AddVectoredExceptionHandler(0, ExceptionHandler);

        // Tell the atomic bool that the handler is now installed
        isExceptionHandlingInitialized.store(true);
    }

    // Encrypt the function
    encryptFunction(functionAddress, functionSize);

    // Store the encrypted function in the map
    encryptedFunctions[functionAddress] = this;
}

Scudo::~Scudo() {

    // Decrypt the function
    decryptFunction(functionAddress, functionSize);

    // Lock the mutex to prevent race-conditions
    std::lock_guard<std::mutex> lock(encryptedFunctionsMutex);

    // Remove the encrypted function from the map
    encryptedFunctions.erase(functionAddress);
}

void Scudo::UnprotectAll()
{
    // Call the deconstructor for every function that is already protected
    for (const auto& encryptedFunction : protectedFunctions) {
        encryptedFunction->~Scudo();
    }

    // Check if the handler is initialized
    if (isExceptionHandlingInitialized.load()) { 

        // Remove the exception handler to the stack
        RemoveVectoredExceptionHandler(exceptionHandler);

        // Tell the atomic bool that the handler is no longer installed
        isExceptionHandlingInitialized.store(false);
    }
}

LONG NTAPI Scudo::ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {

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

    // Shorten the pointer chain for simplicity
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


bool Scudo::isEncryptedFunction(void* functionAddress) {
    return encryptedFunctions.find(functionAddress) != encryptedFunctions.end();
}

Scudo* Scudo::getEncryptedFunction(void* functionAddress) {
    std::lock_guard<std::mutex> lock(encryptedFunctionsMutex);
    auto it = encryptedFunctions.find(functionAddress);
    if (it != encryptedFunctions.end()) {
        return it->second;
    }
    return nullptr;
}

Scudo* Scudo::returnAddressToFunction(void* returnAddress) {
    std::lock_guard<std::mutex> lock(encryptedFunctionsMutex);
    for (const auto& pair : encryptedFunctions) {
        Scudo* encryptedFunction = pair.second;
        if (encryptedFunction->lastReturnAddress == reinterpret_cast<uintptr_t>(returnAddress)) {
            return encryptedFunction;
        }
    }
    return nullptr;
}

void Scudo::encryptFunction(void* function, SIZE_T size) {

    // Set the protection
    MemoryProtect memFunction = MemoryProtect(functionAddress, functionSize, PAGE_EXECUTE_READWRITE);

    // Save the first byte for the function
    this->firstByte = *static_cast<BYTE*>(function);

    // Skip the first byte and encrypt the rest
    for (SIZE_T i = 1; i < size; ++i) {
        BYTE* pByte = static_cast<BYTE*>(function) + i; // Get a pointer to the current byte in the function
        *pByte = ~(*pByte);                             // Invert byte bits
        *pByte ^= this->xorKey;                         // XOR the left shifted byte
    }

    // Set the first byte to the debug byte
    *static_cast<BYTE*>(functionAddress) = DEBUG_BYTE;
}

void Scudo::decryptFunction(void* function, SIZE_T size) {

    // Set the protection
    MemoryProtect memFunction = MemoryProtect(function, size, PAGE_EXECUTE_READWRITE);

    // Restore the first byte of the function
    *static_cast<BYTE*>(function) = this->firstByte;

    // Skip the first byte and decrypt the rest
    for (SIZE_T i = 1; i < size; ++i) {
        BYTE* pByte = static_cast<BYTE*>(function) + i; // Get a pointer to the current byte in the function
        *pByte ^= this->xorKey;                         // XOR the right shifted byte
        *pByte = ~(*pByte);                             // Invert byte bits
    }
}

void Scudo::encryptionRoutine()
{
    // Set the protection
    MemoryProtect memFunction = MemoryProtect((PVOID)currentEncryptedFunction->lastReturnAddress, sizeof(BYTE), PAGE_EXECUTE_READWRITE);

    // Reset the return address to normal
    *static_cast<BYTE*>((void*)this->lastReturnAddress) = this->lastReturnAddressByte;

    // Generate a new key to ensure a new encryption
    xorKey = randomKey();

    // Re-Encrypt the function
    this->encryptFunction(this->functionAddress, this->functionSize);
}

void Scudo::decryptionRoutine()
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

inline uint64_t Scudo::randomKey() {
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd; std::mt19937_64 gen(rd()); std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    std::string key(KEY_LENGTH, ' '); for (char& c : key) c = charset[dis(gen)];
    uint64_t intValue = 0; for (char c : key) intValue = intValue * 1000 + c;
    return intValue;
}
#include "B64Encryption.h"

// Initialize static variables
thread_local Scudo* Scudo::currentEncryptedFunction; // A pointer to the currently selected EncryptedFunction

typename Scudo::EncryptedFunctionMap Scudo::encryptedFunctions; // A map of all our encrypted functions

std::atomic<bool> Scudo::isExceptionHandlingInitialized(false); // An atomic bool to determine if the exception handler is already initialized

std::mutex Scudo::encryptedFunctionsMutex; // A mutex to ensure thread safety

std::vector<std::unique_ptr<Scudo>> Scudo::protectedFunctions{};

std::unique_ptr<UserRequestHandler> Scudo::userRequestHandler = nullptr;

PVOID Scudo::exceptionHandler = NULL;

#ifdef AA_USECALLBACK
EXTERN_C VOID topLevelHandler(PEXCEPTION_RECORD exceptionRecord, PCONTEXT contextRecord) {
    // Always check if the user is authenticated
    if (!Scudo::userRequestHandler->isAuthenticated()) {
        RtlRestoreContext(contextRecord, NULL);
        return;
    }

    // If the exception isn't a breakpoint, look for another handler
    if (exceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        RtlRestoreContext(contextRecord, NULL);
        return;
    }

    // Get the address where the exception occured
    void* exceptionAddress = exceptionRecord->ExceptionAddress;

    /*
    * Use INT3 instruction breakpoint at return address found on the stack to trigger an exception which will
    * allow the program to re-encrypt the function immediately after it's done executing.
    */
    if (!Scudo::isEncryptedFunction(exceptionAddress)) // Check if the breakpoint occured at an encrypted function
    {
        // Get the encrypted function's object from the return address associated with it
        if ((Scudo::currentEncryptedFunction = Scudo::returnAddressToFunction(exceptionAddress)), Scudo::currentEncryptedFunction == nullptr) {
            RtlRestoreContext(contextRecord, NULL);
            return;
        }

        // Re-encrypt the function aswell as remove the breakpoint from the return address
        Scudo::currentEncryptedFunction->encryptionRoutine();

        contextRecord->EFlags |= (1 << 16);
        RtlRestoreContext(contextRecord, NULL);
        return;
    }

    // Get the encrypted function's object
    if ((Scudo::currentEncryptedFunction = Scudo::getEncryptedFunction(exceptionAddress)), Scudo::currentEncryptedFunction == nullptr) {
        RtlRestoreContext(contextRecord, NULL);
        return;
    }

    // Create a pointer to the rspAddress
    uintptr_t* returnAddressPtr = reinterpret_cast<uintptr_t*>(contextRecord->Rsp);

    // Dereference the pointer to retrieve the return address value
    Scudo::currentEncryptedFunction->lastReturnAddress = *returnAddressPtr;

    // Decrypts the function and puts breakpoint on return address
    Scudo::currentEncryptedFunction->decryptionRoutine();

    // Resume execution
    contextRecord->EFlags |= (1 << 16);
    RtlRestoreContext(contextRecord, NULL);
    return;
}
#endif // !AA_USECALLBACK



void AAPROTECT(void* functionAddress) {
    // Always check if the user is authenticated
    if (!Scudo::userRequestHandler->isAuthenticated())
        return;

    Scudo::protectedFunctions.push_back(std::make_unique<Scudo>(functionAddress));
}

void AAUNPROTECT() {
    // Always check if the user is authenticated
    if (!Scudo::userRequestHandler->isAuthenticated())
        return;

    Scudo::UnprotectAll();
}

void AAInit(std::string userEmail, std::string userToken) {

    // Initialize The Request Handler
    Scudo::userRequestHandler = std::make_unique<UserRequestHandler>(userEmail, userToken);

    // Send the request to our server
    Scudo::userRequestHandler->sendUserRequest(x_("auth.asylus.online"), x_("8080"));
}

Scudo::Scudo(void* functionAddress)
    : functionAddress(functionAddress), 
    functionSize(GetFunctionLength(functionAddress)) {

    // Ensure valid function pointer was passed
    if (!functionAddress || !functionSize)
        throw std::invalid_argument(x_("Invalid functionAddress or functionSize"));

    // Always check if the user is authenticated
    if (!userRequestHandler->isAuthenticated())
        return;
        
    // Set the XOR byte to a random value (TODO - Encrypt with a 3 sequencial xor operations with 3 xor keys)
    xorKey = randomKey();

    // Check if the handler has already been initialized
    if (!isExceptionHandlingInitialized.load()) {

        // Install our exception handler
#ifndef AA_USECALLBACK
        exceptionHandler = ShadowCall<PVOID>(shadow::hash_t(x_("RtlAddVectoredExceptionHandler")), 1, ExceptionHandler);
#else
        InstallCallback(true);
#endif // !AA_USECALLBACK

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
#ifndef AA_USECALLBACK
        ShadowCall<ULONG>(shadow::hash_t(x_("RtlRemoveVectoredExceptionHandler")), exceptionHandler);
#else
        InstallCallback(false);
#endif // !AA_USECALLBACK     

        // Tell the atomic bool that the handler is no longer installed
        isExceptionHandlingInitialized.store(false);
    }
}

LONG NTAPI Scudo::ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {

    // Always check if the user is authenticated
    if (!userRequestHandler->isAuthenticated())
        return EXCEPTION_CONTINUE_SEARCH;

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
    *static_cast<BYTE*>(functionAddress) = BREAKPOINT_BYTE;
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
    *static_cast<BYTE*>((PVOID)this->lastReturnAddress) = this->lastReturnAddressByte;

    // Generate a new key to ensure a new encryption
    this->xorKey = randomKey();

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
    *reinterpret_cast<BYTE*>(currentEncryptedFunction->lastReturnAddress) = BREAKPOINT_BYTE;

    // Decrypt the function
    currentEncryptedFunction->decryptFunction(currentEncryptedFunction->functionAddress, currentEncryptedFunction->functionSize);
}

inline uint64_t Scudo::randomKey() {

    // Encrypted array representing 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
    static unsigned char alphaNumericCharacters[] =
    {

        0x4c, 0xc5, 0x45, 0xc2, 0x4a, 0xcb, 0x4b, 0xc8,
        0x48, 0xd1, 0x2d, 0xad, 0x2a, 0xb2, 0x33, 0xb3,
        0x30, 0xb0, 0x39, 0xb9, 0x36, 0xbe, 0x3f, 0xbf,
        0x3c, 0xbc, 0x35, 0xb5, 0x32, 0xba, 0x3b, 0xbb,
        0x38, 0xb8, 0x1, 0x81, 0xdd, 0x5d, 0xda, 0x22,
        0xa3, 0x23, 0xa0, 0x20, 0x29, 0xa9, 0xa6, 0xae,
        0x2f, 0xaf, 0x2c, 0xac, 0x25, 0xa5, 0xa2, 0xaa,
        0x2b, 0xab, 0x28, 0xa8, 0x31, 0xb1, 0x74
    };

    // Prevent excessive math when generating a new key
    static bool decrypted = false;

    // Decrypt the array upon first call
    if (!decrypted) {
        for (unsigned int index = 0; index < sizeof(alphaNumericCharacters); ++index)
        {
            unsigned char c = alphaNumericCharacters[index];
            c = ~c;
            c ^= 0x9d;
            c = -c;
            c = ~c;
            c -= 0x46;
            c = (c >> 0x7) | (c << 0x1);
            c ^= 0xd;
            c += index;
            c = ~c;
            c = -c;
            c -= index;
            c ^= 0xf8;
            c -= 0x49;
            c ^= 0x22;
            c = -c;
            alphaNumericCharacters[index] = c;
        }
        decrypted = true;
    }

    // Initialize randomized information
    std::random_device rd; 
    std::mt19937_64 gen(rd()); 
    std::uniform_int_distribution<> dis(0, sizeof(alphaNumericCharacters) - 2);
    std::string key(KEY_LENGTH, ' '); 

    // Populate all characters in the key with random characters
    for (char& c : key) 
        c = alphaNumericCharacters[dis(gen)];

    // Generate a new Xor Key value
    uint64_t intValue = 1; 
    for (char c : key) {
        intValue *= 1000;
        intValue += c;
    }

    return intValue;
}
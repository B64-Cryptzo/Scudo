#ifndef SCUDO_H
#define SCUDO_H

#define LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS

#include <A64LazyImporter.h>
#include <A64XorStr.h>
#include <A64Protect.h>
#include <A64Function.h>

constexpr BYTE DEBUG_BYTE = 0xCC; ///< Intel ICE debugging byte
constexpr size_t KEY_LENGTH = 10; ///< Length of the random key

/**
* @brief Library proxy for Scudo class initializer.
*
* Places the function in the protected function list
*
* @param functionAddress The function pointer to be encrypted.
*/
extern void A64PROTECT(void* functionAddress);

/**
* @brief Library proxy to unprotect every function.
*
* Removes the exception handler.
*/
extern void A64UNPROTECT();
 
class Scudo {

public: 
    using EncryptedFunctionMap = std::unordered_map<void*, Scudo*>; // Map to access all encrypted functions

    /**
     * @brief Constructor for Scudo class.
     *
     * Initializer for Scudo that encrypts the function and ensures all variables are set for decryption.
     *
     * @param functionAddress The function pointer to be encrypted.
     * @throws std::invalid_argument If the function address or size is invalid.
     */
    Scudo(void* functionAddress);

    /**
     * @brief Destructor for Scudo class.
     *
     * Ensures that the function is decrypted and all vectors and maps are adjusted.
     */
    ~Scudo();
     
    /**
     * @brief Unprotects all functions and removes the exception handler
     */
    static void UnprotectAll();

    static std::vector<std::unique_ptr<Scudo>> protectedFunctions; ///< List of our protected functions to prevent class from going out of scope after initialization

private:
    /**
     * @brief Exception handler for handling and parsing ICE debug instructions placed on functions.
     *
     * @param exceptionInfo Pointer to the exception information.
     * @return LONG Returns the exception handling status.
     */
    static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo);

    /**
     * @brief Checks if the address passed is the entry point to an already encrypted function.
     *
     * @param functionAddress The function address to check.
     * @return true If the function is already encrypted.
     * @return false Otherwise.
     */
    static bool isEncryptedFunction(void* functionAddress);

    /**
     * @brief Returns the class object of the function encrypted at the passed address.
     *
     * @param functionAddress The function address to retrieve the class object for.
     * @return Scudo* Pointer to the Scudo object.
     */
    static Scudo* getEncryptedFunction(void* functionAddress);

    /**
     * @brief Returns the class object of the function encrypted with the specified return address.
     *
     * @param returnAddress The return address to retrieve the class object for.
     * @return Scudo* Pointer to the Scudo object.
     */
    static Scudo* returnAddressToFunction(void* returnAddress);

    /**
     * @brief Encrypts the function using B64 encryption.
     *
     * @param function The function to encrypt.
     * @param size The size of the function.
     */
    void encryptFunction(void* function, SIZE_T size);

    /**
     * @brief Decrypts the function by XORing with the debug byte.
     *
     * @param function The function to decrypt.
     * @param size The size of the function.
     */
    void decryptFunction(void* function, SIZE_T size);

    /**
     * @brief Routine for the handler to re-encrypt the function immediately after it finishes executing.
     */
    void encryptionRoutine();

    /**
     * @brief Routine for the handler to decrypt the function immediately after being called.
     */
    void decryptionRoutine();

    /**
     * @brief Generates a new key every time the function needs to be re-encrypted.
     *
     * @return uint64_t The generated random key.
     */
    inline uint64_t randomKey();

    // For encryption and decryption
    void* functionAddress;     ///< Address of the function.
    SIZE_T functionSize;       ///< Size of the function.

    // For decryption
    BYTE firstByte;            ///< First byte of the function.

    // For Encryption
    uint64_t xorKey;           ///< XOR key for encryption.
    uintptr_t lastReturnAddress; ///< Last return address for decryption.
    BYTE lastReturnAddressByte; ///< Last return address byte for decryption.

    // For Handler
    static thread_local Scudo* currentEncryptedFunction; ///< Pointer to the currently selected encrypted function.
    static EncryptedFunctionMap encryptedFunctions;      ///< Map of all encrypted functions.
    static std::atomic<bool> isExceptionHandlingInitialized; ///< Atomic bool to determine if the exception handler is already initialized.
    static std::mutex encryptedFunctionsMutex;              ///< Add mutex for thread safety
    static PVOID exceptionHandler;                          ///< Exception handler.
};

#endif // SCUDO_H
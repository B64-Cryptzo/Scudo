#ifndef AA_INIT_A
#define AA_INIT_A

#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winternl.h>

#include <A64XorStr.h>
#include <A64LazyImporter.h>
#include <AADecryption.h>

#pragma comment(lib, "Ws2_32.lib")

class UserRequestHandler {
public:
    enum AA_STATUS_CODES {
        authenticated = 101,
        failed_to_authenticate = 202,
        wsastartup_failed = 303,
        getaddrinfo_failed = 404,
        failed_to_connect_to_server = 505,
        failed_to_send = 606,
        failed_to_recv = 707,
        hash_tampered = 808,
        timestamp_doesnt_match = 909
    };

    UserRequestHandler(std::string userEmail, std::string userToken) : serverRequest({ .email = userEmail, .token = userToken }) {};

    AA_STATUS_CODES sendUserRequest(const char* serverAddress, const char* port) {
        WSADATA wsaData;
        SOCKET connectSocket = INVALID_SOCKET;
        struct addrinfo* result = nullptr, hints = { 0 };

        if (ShadowCall<int>(shadow::hash_t(x_("WSAStartup")), MAKEWORD(2, 2), &wsaData) != 0) { // WSAStartup(MAKEWORD(2, 2), &wsaData)
            statusCode = wsastartup_failed;
            return statusCode;
        }

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (getaddrinfo(serverAddress, port, &hints, &result) != 0) {
            ShadowCall<int>(shadow::hash_t(x_("WSACleanup")));
            statusCode = getaddrinfo_failed;
            return statusCode;
        }

        for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            if ((connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol)) == INVALID_SOCKET) continue;
            if (ShadowCall<int>(shadow::hash_t(x_("connect")), connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) != SOCKET_ERROR) break;
            ShadowCall<int>(shadow::hash_t(x_("closesocket")), connectSocket);
            connectSocket = INVALID_SOCKET;
        }

        freeaddrinfo(result);
        if (connectSocket == INVALID_SOCKET) {
            ShadowCall<int>(shadow::hash_t(x_("WSACleanup")));
            statusCode = failed_to_connect_to_server;
            return statusCode;
        }

        // Get current timestamp
        auto duration = std::chrono::system_clock::now().time_since_epoch();

        // Cast the timestamp to seconds
        long long currentTimestamp = std::chrono::duration_cast<std::chrono::seconds>(duration).count();

        // Generate our server request data
        std::string userClientData = "email=" + serverRequest.email + "&token=" + serverRequest.token + "&timestamp=" + std::to_string(currentTimestamp);

        // Hash and append our hash to the data
        std::string userClientDataHashed = userClientData + "&hash=" + std::to_string(hash(userClientData.data(), "AsylusLibrary"));

        // Construct our HTTP header and request
        std::string hostHeader = "Host: " + std::string(serverAddress) + "\r\n";
        std::string userAgentHeader = "User-Agent: AsylusLibrary\r\n";
        std::string contentTypeHeader = "Content-Type: application/x-www-form-urlencoded\r\n";
        std::string contentLengthHeader = "Content-Length: " + std::to_string(userClientDataHashed.size()) + "\r\n";
        std::string connectionHeader = "Connection: close\r\n";
        std::string headers = "POST / HTTP/1.1\r\n" + hostHeader + userAgentHeader + contentTypeHeader + contentLengthHeader + connectionHeader + "\r\n";
        headers += userClientDataHashed;

        // Send the request
        if (ShadowCall<int>(shadow::hash_t(x_("send")), connectSocket, headers.data(), headers.size(), 0) == SOCKET_ERROR) {
            ShadowCall<int>(shadow::hash_t(x_("closesocket")), connectSocket);
            ShadowCall<int>(shadow::hash_t(x_("WSACleanup")));
            statusCode = failed_to_send;
            return statusCode;
        }

        char serverResponse[1024];
        int responseLength;

        // Read the response
        if ((responseLength = ShadowCall<int>(shadow::hash_t(x_("recv")), connectSocket, serverResponse, sizeof(serverResponse), 0)) == SOCKET_ERROR) {
            ShadowCall<int>(shadow::hash_t(x_("closesocket")), connectSocket);
            ShadowCall<int>(shadow::hash_t(x_("WSACleanup")));
            statusCode = failed_to_recv;
            return statusCode;
        }

        ShadowCall<int>(shadow::hash_t(x_("closesocket")), connectSocket);
        ShadowCall<int>(shadow::hash_t(x_("WSACleanup")));

        // Parsing the HTTP response body
        std::string responseStr(serverResponse, responseLength);

        // Get the end of our header
        size_t headerEnd = responseStr.find("\r\n\r\n");

        // If we found data continue parsing
        if (headerEnd != std::string::npos) {

            // The body starts 4 bytes after the end of the header
            std::string body = responseStr.substr(headerEnd + 4);

            // Check if our body is at least the expected size of the encrypted string (32 bytes)
            if (body.size() >= 32) {

                // Extract the encrypted string
                std::string encryptedString = body.substr(0, 32);

                // Decrypt the encrypted string
                Decrypt decryptor(encryptedString);

                // Retrieve the value
                int receivedCode = decryptor.getDecryptedValue();

                statusCode = static_cast<AA_STATUS_CODES>(receivedCode);
            }
        }

        return statusCode;
    }

    bool isAuthenticated() {

        static bool errorMessageDisplayed = false;

        // Return if the user is authenticated
        if (statusCode == UserRequestHandler::authenticated)
            return true;

        if (errorMessageDisplayed)
            return false;

        // Define your cBody and cCaption strings
        static wchar_t* cBody = x_(L"");
        static wchar_t* cCaption = x_(L"Could not authenticate");

        switch (statusCode)
        {
        case UserRequestHandler::failed_to_authenticate:
            cBody = x_(L"Please ensure you entered your email and token properly");
            break;
        case UserRequestHandler::wsastartup_failed:
            cBody = x_(L"WSAStartup Failed");
            break;
        case UserRequestHandler::getaddrinfo_failed:
            cBody = x_(L"Failed to get server information");
            break;
        case UserRequestHandler::failed_to_connect_to_server:
            cBody = x_(L"Failed to connect to server");
            break;
        case UserRequestHandler::failed_to_send:
            cBody = x_(L"Failed to send information to server");
            break;
        case UserRequestHandler::failed_to_recv:
            cBody = x_(L"Failed to receive information from server");
            break;
        case UserRequestHandler::timestamp_doesnt_match:
            exit(909);
            break;
        default:
            break;
        }

        // Initialize UNICODE_STRING structs
        UNICODE_STRING msgBody;
        UNICODE_STRING msgCaption;

        // Set the Buffer and Length for msgBody
        msgBody.Buffer = cBody;
        msgBody.Length = wcslen(cBody) * sizeof(wchar_t);
        msgBody.MaximumLength = msgBody.Length + sizeof(wchar_t);

        // Set the Buffer and Length for msgCaption
        msgCaption.Buffer = cCaption;
        msgCaption.Length = wcslen(cCaption) * sizeof(wchar_t);
        msgCaption.MaximumLength = msgCaption.Length + sizeof(wchar_t);

        ULONG ErrorResponse;

        const ULONG_PTR msgParams[] = {
        (ULONG_PTR)&msgBody,
        (ULONG_PTR)&msgCaption,
        (ULONG_PTR)(MB_OK | MB_ICONINFORMATION)
        };

        ShadowCall<int>(shadow::hash_t(x_("ZwRaiseHardError")), 0x50000018L, 0x00000003L, 3, (PULONG_PTR)msgParams, NULL, &ErrorResponse);

        errorMessageDisplayed = true;

        return false;
    }

    AA_STATUS_CODES statusCode = failed_to_authenticate;

private:
    struct UserRequest {
        std::string email, token;
    };

    unsigned int hash(const char* str, const char* salt) {
        unsigned int hash = 5381;
        int character;

        // Hash the salt
        while ((character = *salt++)) {
            hash = ((hash << 5) + hash) + character; // hash * 33 + c
        }

        // Hash the input string
        while ((character = *str++)) {
            hash = ((hash << 5) + hash) + character; // hash * 33 + c
        }

        return hash;
    }

    UserRequest serverRequest;
};
#endif // AA_INIT_A
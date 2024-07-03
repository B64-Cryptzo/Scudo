#ifndef AA_DECRYPT_H
#define AA_DECRYPT_H

#include <sstream>
#include <string>
#include <ctime>
#include <iostream>

class Decrypt {
public:
    Decrypt(const std::string& encryptedString) {
        decryptedValue = decrypt(encryptedString);
    }

    int getDecryptedValue() const {
        return decryptedValue;
    }

private:
    int decryptedValue;


    static int decrypt(const std::string& encryptedString) {

        // Get the last character from the random string
        char lastChar = encryptedString[31];

        // Get the integer value to use as our index into the string
        int reponseCodeLength = hexStrToInt(std::string(1, lastChar));

        // Retreive the rotated, xored, hex representation of our response code at index 17
        std::string xoredHex = encryptedString.substr(17, reponseCodeLength);

        // Convert the rotated, xored, hex response to a rotated, xored response
        int xoredResponseCode = hexStrToInt(xoredHex);

        // Get the start index of our reversed, rotated, xored, hex unix timestamp
        int unixTimestampIndex = 8;

        // Get our reversed, rotated, xored, hex unix timestamp
        std::string reversedTimestampHex = encryptedString.substr(unixTimestampIndex, 8);

        // Reverse the modified timestamp
        std::string timestampHex = reverseString(reversedTimestampHex);

        // Get our rotated, xored unix timestamp
        int modifiedTimestamp = hexStrToInt(timestampHex);

        // Xor our rotated, xored unix timestamp
        modifiedTimestamp ^= hexStrToInt(std::string(6, encryptedString.substr(0, 1)[0]));

        // Right rotated our unix timestamp
        int timestamp = ror(modifiedTimestamp, 13);

        // We will rotate our response by the value of the first character divided by 2
        int shiftAmount = hexStrToInt(encryptedString.substr(0, 1)) / 2;

        // Rotate and Xor our rotated and xored response code
        int responseCode = rol(xoredResponseCode, shiftAmount) ^ timestamp;

        // Get the current unix timestamp
        int currentTimestamp = static_cast<int>(std::time(nullptr));

        // Check if the difference between our local timestamp and server timestamp is 5 seconds
        if (absoluteValue(currentTimestamp - timestamp) > 5)
            responseCode = 909;

        // Return our response
        return responseCode;
    }

    template<class T>
    static inline T __ROL__(T value, int count)
    {
        const unsigned int nbits = sizeof(T) * 8;

        if (count > 0)
        {
            count %= nbits;
            T high = value >> (nbits - count);
            if (T(-1) < 0) // signed value
                high &= ~((T(-1) << count));
            value <<= count;
            value |= high;
        }
        else
        {
            count = -count % nbits;
            T low = value << (nbits - count);
            value >>= count;
            value |= low;
        }
        return value;
    }

    static inline unsigned int rol(unsigned int value, int count) { return __ROL__((unsigned int)value, count); }

    static inline unsigned int ror(unsigned int value, int count) { return __ROL__((unsigned int)value, -count); }

    static inline int absoluteValue(int value) {
        return value < 0 ? -value : value;
    }

    static inline std::string reverseString(const std::string& str) {
        return std::string(str.rbegin(), str.rend());
    }

    static inline unsigned int hexStrToInt(const std::string& hexStr) {
        unsigned int num;
        std::stringstream ss;
        ss << std::hex << hexStr;
        ss >> num;
        return num;
    }
};


#endif //! AA_DECRYPT_H
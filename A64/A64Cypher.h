#include <Windows.h>
#include <random>
#include <string>
#include <chrono>
#include <iostream>

using namespace std;


#define XORWORD(word, xval) for(auto m = 0; m < sizeof(decltype(xval)); ++m) word ^= reinterpret_cast<unsigned char*>(&xval)[m] \

typedef unsigned long long XORKEY;
/*	
	Class used for generating a using cypher key based on a technique refered 
	to as, "Polyc 3-dimensional Polymorphic Encryption Algorithm Prototype" 
	by Chemiculs 
*/
class B64Cypher
{
private:
	auto strongSeed() {
		// Initializes the random_device class
		std::random_device rd;

		// Initializes a seeding value comprised of 4 unique entropic values and a system timestamp
		std::seed_seq seed{
			rd(), rd(), rd(), rd(),
				static_cast<unsigned int>(std::chrono::high_resolution_clock::now().time_since_epoch().count()) 
		};

		// Seed generator using the previously initialized seed sequence
		std::mt19937_64 gen(seed);

		// Generate a random number to determine the math operation
		std::uniform_int_distribution<unsigned long long> limit(0, 7);

		std::uniform_int_distribution<unsigned long long> limit_key(16, 1024);

		switch (limit(gen))
		{
		case 0:
			return (limit_key(gen) * limit_key(gen));
		case 1:
			return (limit_key(gen) / limit_key(gen));
		case 2:
			return (limit_key(gen) - limit_key(gen));
		case 3:
			return (limit_key(gen) + limit_key(gen));
		case 4:
			return (limit_key(gen) ^ limit_key(gen));
		case 5:
			return (limit_key(gen) | limit_key(gen));
		case 6:
			return (limit_key(gen) & limit_key(gen));
		case 7:
			return (limit_key(gen) % limit_key(gen));
		default:
			break;
		}
	};
	void refreshCiphers()
	{
		if (privateKeys.timesUsed < 2) privateKeys.timesUsed++; return; // Allow every key pair to be used twice, Once for encryption and once for decryption

		// Refresh every seed
		for (int i = 0; i < 16; i++)
		{
			privateKeys.RotationalArray[i] = strongSeed();
		}

		for (int i = 0; i < 3; i++)
		{
			privateKeys.RotationalIndices[i] = rand() % 16;
		}

		// Reset times used to allow for another routine
		privateKeys.timesUsed = 0;
	}
	typedef struct RotationalXorKeys
	{
		int RotationalArray[16]; // Every class instance will have an array of 16 unique keys
		int RotationalIndices[3]; // Every class will have three randomly assigned indices
		int timesUsed;
	}RXK;
	
	RXK privateKeys;
	XORKEY xLockKey;
public:
	B64Cypher() { cout << (int)this->strongSeed() << endl; };
	~B64Cypher() { };
};
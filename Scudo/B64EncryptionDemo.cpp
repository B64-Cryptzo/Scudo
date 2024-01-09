#include "B64Encryption.h"
int Add(int a, int b)
{
	return a+b;
}
 
int main()
{
	std::cout << ".oOOOo.                    o       \no     o                   O        \nO.                        o        \n `OOoo.                   o        \n      `O .oOo  O   o  .oOoO  .oOo. \n       o O     o   O  o   O  O   o \nO.    .O o     O   o  O   o  o   O \n `oooO'  `OoO' `OoO'o `OoO'o `OoO' \n			by Cryptzo\n\n";

	std::cout << "[ ! ] Target Function Address - 0x" << &Add << "\n";

	std::cout << "[ + ] Result Before encryption: " << Add(1, 1) << "\n[ ... ] Press any key to encrypt";

	std::cin.get();

	std::unique_ptr<Scudo> newFunction(new Scudo(&Add));
	
	std::cout << "[ + ] Result After encryption: " << Add(1, 1) << "\n";

	std::cin.get();

	return 0;
}
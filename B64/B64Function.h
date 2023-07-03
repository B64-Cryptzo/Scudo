#pragma once
#include <windows.h>
#include "../B64/B64Opcode.h"


std::int32_t GetFunctionLength(void* function) {

	if (!function)
		return 0;

	PCHAR functionAddress = PCHAR(function); //Address to start
	unsigned long functionSize = 0ul; //Function Size

	// Make sure this is actually a valid address
	while (functionAddress && *PWORD(functionAddress) != 0xCCCC) { //while valid address and value at address isnt breakpoint
		// Calculate the size of the instruction

		
		size_t instructionSize = OpDisassemble(functionAddress).GetLength();
		// Size of INT3 is 1 byte. If the following byte is also 0xCC with a size of 1 also, chances are, we've reached the end of the function.
		if (instructionSize == 1 && OpDisassemble(functionAddress + 1).GetLength() == 1 && (*PWORD(functionAddress) == 0xCCCC))
			break;
		// Iterate past
		functionSize += instructionSize;
		functionAddress += instructionSize;
	}
	return functionSize;
}
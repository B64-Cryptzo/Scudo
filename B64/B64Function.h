#pragma once
#include <windows.h>
#include "../B64/B64Opcode.h"

inline std::int32_t GetFunctionLength(void* function) {

	if (!function)
		return 0;

	// Start Address
	PCHAR functionAddress = PCHAR(function);

	// Our return variable
	std::int32_t functionLength = 0;

	// Loop untill we reach double int3 breakpoints
	while (functionAddress && *PWORD(functionAddress) != 0xCCCC) { //while valid address and value at address isnt breakpoint
		
		// Get the size of the instruction
		size_t instructionSize = OpDisassemble(functionAddress).GetLength();

		// Check if double int3 is two seperate instructions
		if (instructionSize == 0x1 && OpDisassemble(functionAddress + 1).GetLength() == 0x1 && (*PWORD(functionAddress) == 0xCCCC))
			break;
		
		// Increment to the next instruction
		functionLength += instructionSize;
		functionAddress += instructionSize;
	}
	return functionLength;
}

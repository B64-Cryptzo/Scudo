#pragma once
#include <windows.h>
#include <A64Opcode.h>

inline std::int32_t GetFunctionLength(void* function) {

	if (!function)
		return 0;

	// Start Address
	PCHAR functionAddress = PCHAR(function);

	// Our return variable
	std::int32_t functionLength = 0;

	/* Loop untill we reach double int3 breakpoints
	 The issue is that int3 are used as padding between functions
	 Even with optimizations off, there could be 1 padding instruction 
	 or 0 which would cause us to trigger exceptions outside the function.
	 We should check either C3 CC (ret, int3) or E9 ?? ?? ?? ?? CC (jmp xyz, int3)
	 or create a list of all functions the program recognizes in the pdb and check 
	 the end address using the start address of functions nearby in memory
	*/
	while (functionAddress) { // while valid address
		
		// Get the size of the instruction
		size_t instructionSize = OpDisassemble(functionAddress).GetLength();

		// Check if double int3 is two seperate instructions
		if (instructionSize == 0x1 && OpDisassemble(functionAddress + 1).GetLength() == 0x1 && (*PWORD(functionAddress) == 0xCCC3)) {
			functionLength += instructionSize;
			break;
		}
			
		// Increment to the next instruction
		functionLength += instructionSize;
		functionAddress += instructionSize;
	}
	return functionLength;
}

inline std::int32_t GetFunctionLength2(void* function) {
	if (!function)
		return 0;

	// Start Address
	PCHAR functionAddress = reinterpret_cast<PCHAR>(function);

	// Our return variable
	std::int32_t functionLength = 0;

	// Loop until we encounter a return instruction (opcode C3)
	while (true) {
		std::uint8_t opcode;

		// Disassemble the instruction
		auto disassembledInstruction = OpDisassemble(functionAddress);

		// Get the size of the instruction and its opcode
		size_t instructionSize = disassembledInstruction.GetLength();

		// Check if the opcode is a ret and the size is 1 byte
		if (instructionSize == 1 && disassembledInstruction.GetOpcode() == 0xC3) {
			break;
		}

		// Check if the opcode is a double int3 indicating passing
		if (instructionSize == 1 && OpDisassemble(functionAddress + 1).GetLength() == 1 && (*PBYTE(functionAddress) == 0xCC)) {
			break;
		}

		// Increment to the next instruction
		functionLength += static_cast<std::int32_t>(instructionSize);
		functionAddress += instructionSize;

		// Optional: Add boundary checks or other conditions here
		// For example, limit the maximum function length or handle invalid instructions
	}

	return functionLength;
}

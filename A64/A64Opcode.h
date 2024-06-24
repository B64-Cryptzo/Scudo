#pragma once
#include <iostream>
#include <cstdint>

#include <capstone/capstone.h>

#pragma comment(lib, "capstone.lib")


class OpDisassemble {
public:
    OpDisassemble(const char* address) {
        // Initialize Capstone
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle_) != CS_ERR_OK) {
            std::cerr << "Failed to initialize Capstone" << std::endl;
            return;
        }

        // Set up disassembly options
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);

        // Perform disassembly
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(handle_, reinterpret_cast<const uint8_t*>(address), 16, reinterpret_cast<uint64_t>(address), 0, &insn);
        if (count > 0) {
            length_ = insn[0].size; // Get the length of the instruction
            mnemonic_ = insn[0].mnemonic; // Get the mnemonic of the instruction
            op_str_ = insn[0].op_str; // Get the operand string of the instruction
            cs_free(insn, count); // Free memory allocated by Capstone
        }
    }

    ~OpDisassemble() {
        cs_close(&handle_); // Clean up Capstone handle
    }

    size_t GetLength() const {
        return length_;
    }

    const char* GetMnemonic() const {
        return mnemonic_;
    }

    const char* GetOperandString() const {
        return op_str_;
    }

private:
    csh handle_;
    size_t length_;
    const char* mnemonic_;
    const char* op_str_;
};
import subprocess
import tempfile
import os
import shutil

def check_tool_availability(tool_name: str) -> bool:
    """Checks if a command-line tool is available in PATH."""
    return shutil.which(tool_name) is not None

def compile_c_to_shellcode(c_code: str, arch: str = "64") -> bytes | None:
    """
    Compiles C code to raw binary shellcode.

    Args:
        c_code: A string containing the C source code.
                The C code should be self-contained and position-independent.
                It should not rely on libc functions unless they are resolved dynamically
                or it's for very simple cases where the linker might optimize them out
                with -nostdlib (unlikely for anything complex).
                Typically, shellcode uses direct syscalls.
        arch: Architecture, "32" or "64". Determines -m32 or -m64 flag for gcc.

    Returns:
        A bytes object containing the raw shellcode, or None on failure.
    """
    if not check_tool_availability("gcc"):
        print("Error: gcc is not installed or not in PATH.")
        return None
    if not check_tool_availability("objcopy"):
        print("Error: objcopy is not installed or not in PATH.")
        return None

    if arch not in ["32", "64"]:
        print(f"Error: Invalid architecture '{arch}'. Must be '32' or '64'.")
        return None

    arch_flag = f"-m{arch}"

    with tempfile.TemporaryDirectory() as tmpdir:
        c_file_path = os.path.join(tmpdir, "source.c")
        obj_file_path = os.path.join(tmpdir, "source.o")
        bin_file_path = os.path.join(tmpdir, "source.bin")

        with open(c_file_path, "w") as f:
            f.write(c_code)

        # Compile C to object file
        # -fPIC: Position Independent Code
        # -nostdlib: Don't link with standard library (makes it smaller, but means no printf etc.)
        # -nostartfiles: Don't use standard startup files
        # -Os: Optimize for size
        # -fdata-sections -ffunction-sections: Useful for objcopy to isolate .text
        # -Wl,--gc-sections (linker flag, but we use -c, so linker not fully run)
        # For pure shellcode, we might need to avoid even the .o format's overhead and use an assembler.
        # However, for simple C snippets, this approach is common.
        # A C function needs to be self-contained.
        # To make it truly position independent and small, one might use inline assembly for syscalls.

        # Note: for shellcode, C functions often need to be carefully written,
        # e.g., avoiding global variables, string literals in certain ways, or complex libc calls.
        # This compiler will just compile what's given.
        gcc_cmd = [
            "gcc", arch_flag, "-fPIC", "-Os",
            "-c", c_file_path, "-o", obj_file_path,
            "-nostdlib", "-nostartfiles",
            "-ffunction-sections", # Helps ensure only used code is in .text of that function
        ]
        # print(f"Executing: {' '.join(gcc_cmd)}")
        compile_proc = subprocess.run(gcc_cmd, capture_output=True)

        if compile_proc.returncode != 0:
            print(f"Error compiling C code with gcc (return code {compile_proc.returncode}):")
            print(f"GCC STDOUT:\n{compile_proc.stdout.decode(errors='ignore')}")
            print(f"GCC STDERR:\n{compile_proc.stderr.decode(errors='ignore')}")
            return None

        # Extract .text section to raw binary
        objcopy_cmd = [
            "objcopy", "-O", "binary", "-j", ".text", obj_file_path, bin_file_path
        ]
        # print(f"Executing: {' '.join(objcopy_cmd)}")
        objcopy_proc = subprocess.run(objcopy_cmd, capture_output=True)

        if objcopy_proc.returncode != 0:
            print(f"Error extracting .text section with objcopy (return code {objcopy_proc.returncode}):")
            print(f"objcopy STDOUT:\n{objcopy_proc.stdout.decode(errors='ignore')}")
            print(f"objcopy STDERR:\n{objcopy_proc.stderr.decode(errors='ignore')}")
            return None

        if not os.path.exists(bin_file_path) or os.path.getsize(bin_file_path) == 0:
            print("Error: objcopy did not produce a binary file or the file is empty.")
            print("This might happen if the C code is empty, contains no functions, or .text section is empty.")
            return None

        with open(bin_file_path, "rb") as f:
            shellcode = f.read()

        return shellcode

if __name__ == '__main__':
    print("Testing C-to-Shellcode Compilation Utility...")

    if not check_tool_availability("gcc") or not check_tool_availability("objcopy"):
        print("gcc or objcopy not found. Skipping tests.")
    else:
        # Test Case 1: Simple 64-bit C code (just a NOP sled like behavior or simple arithmetic)
        # A function that does nothing useful but compiles.
        # Standard library functions like printf won't work with -nostdlib easily.
        # For shellcode, one would typically use syscalls via inline assembly.
        # This example is just to test the compilation pipeline.
        c_code_64_simple_return = """
        int _start() { // Using _start can sometimes simplify things with -nostdlib
            return 42;
        }
        """
        # If _start is not found by objcopy, it might be because gcc optimizes it away if it's truly empty.
        # Let's try a function that does a bit more.
        c_code_64_arith = """
        // This function needs to be callable or part of .text
        // We are extracting whole .text, so any function here will be part of it.
        // Using a known symbol like '_start' can be helpful if we later want to target it.
        // However, -ffunction-sections means objcopy -j .text might get more than just one function
        // if they are not optimized out.
        // For shellcode, we usually care about a specific function's bytes.
        // A better objcopy command for a specific function: objcopy -O binary -j .text.my_func_name ...
        // But -j .text gets all code.

        // This is a simple function that will generate some instructions.
        // It's not true shellcode (doesn't make syscalls, etc.)
        // but tests the compile & extract process.
        volatile int x = 0; // volatile to prevent optimization away
        int get_val() {
            x = 10;
            x = x * 2;
            x = x + 5;
            return x; // Should be 25
        }
        // To ensure get_val is in .text and not optimized out if unused,
        // we might need a dummy _start or ensure it's not static.
        // With -c, it should be kept.
        """
        # Let's use a very simple function that's likely to produce some code in .text
        c_code_64_basic_func = """
        int my_shellcode_func() {
            int a = 5;
            int b = 10;
            int c = a + b;
            return c; // This code itself isn't "shellcode" but will compile to .text
        }
        // We need _start or main if not -c, but with -c this is fine.
        // The problem is objcopy -j .text will get *all* .text sections.
        // If we want specific function, we need to name the section like .text.my_shellcode_func
        // and tell gcc to put it there via __attribute__((section(".text.my_shellcode_func")))
        // For now, let's try with a simple _start.
        c_code_64_minimal_start = """
        void _start() {
            asm volatile("nop; nop; nop");
        }
        """

        print("\n--- Test 1: Compiling 64-bit C code (minimal _start with NOPs) ---")
        shellcode64 = compile_c_to_shellcode(c_code_64_minimal_start, arch="64")
        if shellcode64:
            print(f"Generated 64-bit shellcode ({len(shellcode64)} bytes): {shellcode64.hex()}")
            assert len(shellcode64) > 0
            # For "nop; nop; nop" (0x90), we expect at least 3 bytes, plus potential function prologue/epilogue
            # if not heavily optimized or if _start isn't special enough.
            # With -nostdlib and -nostartfiles, _start is often the direct entry.
            # Minimal x86_64 _start doing nothing might be just "ret" (0xc3) or very little.
            # The nops should ensure some bytes.
        else:
            print("Failed to generate 64-bit shellcode.")

        # Test Case 2: Simple 32-bit C code
        c_code_32_minimal_start = """
        void _start() {
            // Simple sequence of instructions for 32-bit
            asm volatile(
                "mov eax, 1;"
                "mov ebx, 42;"
                "int 0x80;"    // Example exit syscall for Linux 32-bit
            );
        }
        """
        print("\n--- Test 2: Compiling 32-bit C code (minimal _start with syscall) ---")
        shellcode32 = compile_c_to_shellcode(c_code_32_minimal_start, arch="32")
        if shellcode32:
            print(f"Generated 32-bit shellcode ({len(shellcode32)} bytes): {shellcode32.hex()}")
            assert len(shellcode32) > 0
        else:
            print("Failed to generate 32-bit shellcode.")

        # Test Case 3: Empty C code (should fail or produce empty shellcode)
        print("\n--- Test 3: Compiling empty C code ---")
        empty_c_code = ""
        shellcode_empty = compile_c_to_shellcode(empty_c_code, arch="64")
        if shellcode_empty:
            print(f"Generated shellcode from empty C ({len(shellcode_empty)} bytes): {shellcode_empty.hex()}")
            # Depending on compiler/objcopy, this might be None or empty.
            # The check `os.path.getsize(bin_file_path) == 0` should handle this.
            assert len(shellcode_empty) == 0 # Or it should be None
        else:
            print("Correctly failed or produced no shellcode for empty C.")
            assert shellcode_empty is None

        # Test Case 4: Invalid C code
        print("\n--- Test 4: Compiling invalid C code ---")
        invalid_c_code = "int main() { this is not C; }"
        shellcode_invalid = compile_c_to_shellcode(invalid_c_code, arch="64")
        assert shellcode_invalid is None, "Compilation of invalid C code should fail (return None)."
        print("Correctly failed for invalid C.")

        print("\nC-to-Shellcode Compilation tests completed.")

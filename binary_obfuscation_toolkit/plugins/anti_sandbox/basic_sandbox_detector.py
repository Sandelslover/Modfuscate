import os
import shutil
import tempfile
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin
from binary_obfuscation_toolkit.core.compiler_utils import compile_c_to_shellcode
from binary_obfuscation_toolkit.plugins.section_injection.elf_section_injector import ElfSectionInjectorPlugin # To use the injector
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import P_FLAGS
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


# Minimal C code for an x86_64 Linux program that exits with code 42.
# This will be our initial test shellcode.
C_EXIT_42_X64 = """
void _start() {
    asm volatile(
        "mov $60, %rax;"  // syscall number for exit (60 for x86_64)
        "mov $42, %rdi;"  // exit code 42
        "syscall;"
    );
}
"""
# TODO: Add more sophisticated C anti-sandbox snippets later.
# For now, focus on the mechanism of injection and execution.

class BasicSandboxDetectorPlugin(ObfuscationPlugin):
    """
    Injects and attempts to execute a simple anti-sandbox check (currently a test shellcode).
    WARNING: This plugin modifies the ELF entry point and is highly experimental.
    It may render binaries unusable.
    """

    def get_name(self) -> str:
        return "basic_sandbox_detector"

    def get_description(self) -> str:
        return ("Injects a test shellcode (exit 42) and modifies ELF entry point to run it. "
                "Highly experimental.")

    def get_options_schema(self) -> dict:
        return {
            "shellcode_c_source": {
                "type": "string",
                "description": "C source code for the shellcode to be injected. Defaults to a simple exit(42) program.",
                "default": C_EXIT_42_X64,
                "required": False
            },
            "target_arch": {
                "type": "string",
                "description": "Target architecture for shellcode compilation ('32' or '64'). Must match binary.",
                "default": "64", # Default to 64-bit
                "required": False
            }
            # Future options:
            # - hook_original_entry_point: bool (if false, shellcode must handle full execution or exit)
            # - specific_sandbox_checks: list (e.g., ['username', 'timing'])
        }

    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        if not PYELFTOOLS_AVAILABLE:
            print("Error: pyelftools is not installed. This plugin cannot operate.")
            return False

        options = options or {}
        c_code_for_shellcode = options.get("shellcode_c_source", C_EXIT_42_X64)
        target_arch_str = options.get("target_arch", "64")

        print(f"--- BasicSandboxDetector: Preparing to inject shellcode into '{binary_path}' ---")

        # 0. Determine binary architecture from the binary itself
        try:
            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)
                binary_elf_class = elf.elfclass # 32 or 64
                if str(binary_elf_class) != target_arch_str:
                    print(f"Warning: Specified target_arch '{target_arch_str}' does not match binary's ELF class '{binary_elf_class}'.")
                    print(f"Attempting to compile shellcode for binary's arch: {binary_elf_class}-bit.")
                    target_arch_str = str(binary_elf_class)
        except Exception as e:
            print(f"Error reading ELF class from binary '{binary_path}': {e}")
            return False

        # 1. Compile C code to shellcode
        print(f"Compiling C code for {target_arch_str}-bit shellcode...")
        shellcode = compile_c_to_shellcode(c_code_for_shellcode, arch=target_arch_str)
        if not shellcode:
            print("Error: Failed to compile C code to shellcode.")
            return False
        print(f"Shellcode compiled successfully ({len(shellcode)} bytes).")

        # 2. Create a temporary file for the shellcode payload
        with tempfile.NamedTemporaryFile(delete=False) as tmp_payload_file:
            tmp_payload_file.write(shellcode)
            payload_file_path = tmp_payload_file.name

        # 3. Use ElfSectionInjectorPlugin to inject the shellcode
        #    The section should be marked executable.
        injector = ElfSectionInjectorPlugin()
        # The name of the injected section should be unique or configurable.
        injected_section_name = ".sbxchk"

        injector_options = {
            "payload_file": payload_file_path,
            "section_name": injected_section_name,
            "executable": True
        }

        print(f"Injecting shellcode into section '{injected_section_name}' (marked executable)...")
        # The injector will write to output_path.
        # If ElfSectionInjectorPlugin fails, it should return False and print errors.
        if not injector.obfuscate(binary_path, output_path, options=injector_options):
            print("Error: ElfSectionInjectorPlugin failed to inject the shellcode.")
            os.remove(payload_file_path)
            return False

        os.remove(payload_file_path) # Clean up temp payload file
        print("Shellcode injected as a new section.")

        # 4. Modify the ELF entry point in the output_path file
        #    This requires re-opening the (now modified) output_path file.
        print(f"Modifying ELF entry point in '{output_path}'...")
        try:
            with open(output_path, 'r+b') as f_modified_elf: # Open for reading and writing in binary
                modified_elf = ELFFile(f_modified_elf) # Parse the newly modified ELF

                # Find the virtual address of the injected section
                # The ElfSectionInjectorPlugin sets sh_addr in the section header.
                injected_section_vaddr = None
                for sec in modified_elf.iter_sections():
                    if sec.name == injected_section_name:
                        injected_section_vaddr = sec['sh_addr']
                        break

                if injected_section_vaddr is None or injected_section_vaddr == 0:
                    # sh_addr might be 0 if not properly set by injector or if non-loadable.
                    # The current injector does try to set a calculated sh_addr.
                    print(f"Error: Could not find virtual address for injected section '{injected_section_name}', or it's 0.")
                    print("       This means the section might not be correctly mapped for execution.")
                    print("       Execution will likely fail. This could be due to PHT limitations.")
                    # Allow to proceed to try to set e_entry, but it's unlikely to work if vaddr is 0.
                    # return False # Strict: if no vaddr, assume failure.

                if injected_section_vaddr is not None: # Can be 0 if PIE base.
                    original_entry_point = modified_elf.header['e_entry']
                    print(f"Original entry point: 0x{original_entry_point:x}")
                    print(f"New entry point (start of injected section '{injected_section_name}'): 0x{injected_section_vaddr:x}")

                    # Prepare to overwrite e_entry in the ELF header
                    new_entry_point = injected_section_vaddr

                    # Get ELF header structure and size for overwriting
                    ehdr_struct = modified_elf.structs.Elf_Ehdr
                    ehdr_offset = 0 # ELF header is at the beginning of the file

                    # Create a mutable copy of the header, modify e_entry, then build and write
                    current_header_dict = dict(modified_elf.header)
                    current_header_dict['e_entry'] = new_entry_point

                    modified_header_bytes = ehdr_struct.build(current_header_dict)

                    f_modified_elf.seek(ehdr_offset)
                    f_modified_elf.write(modified_header_bytes)

                    print(f"ELF entry point updated to 0x{new_entry_point:x}.")
                    print("WARNING: The injected shellcode is now the first code to run.")
                    print("         It MUST correctly handle execution flow (e.g., exit or jump back to original entry point).")
                    print("         The current test shellcode (exit 42) will terminate the program.")
                    print("         Also, remember the PHT modification for PT_LOAD is still a major known limitation in the section injector for true code execution.")

                else: # This case was handled above, but as a fallback
                    print(f"Error: Failed to find injected section '{injected_section_name}' to set new entry point.")
                    return False


        except Exception as e:
            print(f"Error modifying ELF entry point in '{output_path}': {e}")
            import traceback
            traceback.print_exc()
            return False

        print(f"--- BasicSandboxDetector: Shellcode injected and entry point modified in '{output_path}' ---")
        return True

if __name__ == '__main__':
    if not PYELFTOOLS_AVAILABLE:
        print("Skipping BasicSandboxDetectorPlugin direct test: pyelftools not installed.")
    elif not compile_c_to_shellcode.check_tool_availability("gcc") or \
         not compile_c_to_shellcode.check_tool_availability("objcopy"):
        print("Skipping BasicSandboxDetectorPlugin direct test: gcc or objcopy not found.")
    else:
        plugin = BasicSandboxDetectorPlugin()

        print(f"Testing plugin: {plugin.get_name()}")
        print(f"Description: {plugin.get_description()}")

        # We need a simple, valid ELF file to test on.
        # Let's try to compile a minimal C program.
        test_dir = "temp_test_antisandbox"
        os.makedirs(test_dir, exist_ok=True)

        source_c_file = os.path.join(test_dir, "test_app.c")
        original_elf_file = os.path.join(test_dir, "test_app.elf")
        obfuscated_elf_file = os.path.join(test_dir, "test_app_antisandbox.elf")

        with open(source_c_file, "w") as f:
            f.write("int main() { return 0; }") # A very simple program

        # Determine host architecture for compiling test_app.elf
        import platform
        host_arch_flag = "-m64" if platform.machine() == "x86_64" else "-m32"
        default_plugin_arch = "64" if host_arch_flag == "-m64" else "32"

        compile_cmd = ["gcc", host_arch_flag, source_c_file, "-o", original_elf_file]
        # For PIE (Position Independent Executable), add -fPIE -pie
        # compile_cmd = ["gcc", host_arch_flag, "-fPIE", "-pie", source_c_file, "-o", original_elf_file]

        print(f"Compiling test ELF: {' '.join(compile_cmd)}")
        compile_proc = subprocess.run(compile_cmd, capture_output=True)

        if compile_proc.returncode != 0:
            print("Failed to compile test_app.c. Skipping plugin test.")
            print(f"GCC STDOUT: {compile_proc.stdout.decode(errors='ignore')}")
            print(f"GCC STDERR: {compile_proc.stderr.decode(errors='ignore')}")
        else:
            print(f"Test ELF '{original_elf_file}' compiled successfully.")

            options = {"target_arch": default_plugin_arch} # Match plugin's shellcode arch to compiled test ELF
            success = plugin.obfuscate(original_elf_file, obfuscated_elf_file, options=options)

            print(f"Plugin obfuscate call successful: {success}")
            if success and os.path.exists(obfuscated_elf_file):
                print(f"Obfuscated file created: '{obfuscated_elf_file}'.")
                os.chmod(obfuscated_elf_file, 0o755) # Make it executable

                print(f"Attempting to run '{obfuscated_elf_file}' to check its exit code...")
                try:
                    # Run the modified ELF. It should exit with code 42 if shellcode runs.
                    # However, due to PHT limitations, it's more likely to crash.
                    # A crash will also result in a non-zero exit code.
                    run_proc = subprocess.run([os.path.abspath(obfuscated_elf_file)], capture_output=True, timeout=5)
                    exit_code = run_proc.returncode
                    print(f"Modified ELF executed. Exit code: {exit_code}")
                    # Note: On some systems, shell might return 128 + signal number for crashes.
                    # e.g., Segfault (signal 11) might give exit code 139.
                    if exit_code == 42:
                        print("SUCCESS: Injected shellcode executed and exited with 42!")
                    elif exit_code != 0: # It crashed or exited with a different code
                        print(f"WARNING: Modified ELF exited with code {exit_code} (expected 42 for successful shellcode, or 0 for original program).")
                        print("         This might indicate a crash due to incomplete ELF modification (e.g., missing PT_LOAD for the new section).")
                        print(f"         STDOUT: {run_proc.stdout.decode(errors='ignore')}")
                        print(f"         STDERR: {run_proc.stderr.decode(errors='ignore')}")
                    else: # Exit code 0
                        print("WARNING: Modified ELF exited with 0. This means the original program ran, not the shellcode, or shellcode jumped to original entry which then exited 0.")

                except subprocess.TimeoutExpired:
                    print("Execution of modified ELF timed out.")
                except Exception as e:
                    print(f"Error running modified ELF: {e}")
            else:
                print("Obfuscation failed or output file not created.")

        # Clean up (optional, comment out to inspect files)
        # shutil.rmtree(test_dir, ignore_errors=True)
        print(f"\nTest files are in '{test_dir}'. Clean up manually if desired.")
        print(f"{plugin.get_name()} self-test complete.")

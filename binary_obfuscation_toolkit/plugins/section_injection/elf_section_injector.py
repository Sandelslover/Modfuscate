import os
import shutil
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import Section, StringTableSection, SymbolTableSection
    from elftools.elf.segments import Segment
    # Note: pyelftools is primarily for reading. Modifying ELF files directly is tricky
    # and often requires careful manual reconstruction or using other tools/libraries
    # designed for ELF modification (e.g., LIEF, or careful manual byte manipulation).
    # For this example, we'll demonstrate the concept, but a robust implementation
    # is significantly more complex and might involve rewriting parts of the ELF.
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False

class ElfSectionInjectorPlugin(ObfuscationPlugin):
    """
    Injects a payload from a file into a new section in an ELF binary.
    WARNING: This is a simplified conceptual implementation. Robust ELF modification
    is very complex and this plugin might render binaries unusable.
    It primarily demonstrates the plugin structure and basic ELF interaction.
    A production-grade tool would require a more sophisticated ELF manipulation library
    or approach (like LIEF or rewriting the ELF structure carefully).
    """

    def get_name(self) -> str:
        return "elf_section_injector"

    def get_description(self) -> str:
        return "Injects a payload from a file into a new section in an ELF binary (experimental)."

    def get_options_schema(self) -> dict:
        return {
            "payload_file": {
                "type": "string",
                "description": "Path to the file containing the payload to inject.",
                "required": True
            },
            "section_name": {
                "type": "string",
                "description": "Name for the new section.",
                "default": ".injected",
                "required": False
            },
            "executable": {
                "type": "boolean",
                "description": "Mark the new section as executable (RX).",
                "default": False,
                "required": False
            }
            # We might also need options for section flags (SHF_WRITE, SHF_ALLOC etc.)
            # For now, we'll try to make it RX if executable is true, R otherwise.
        }

    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        if not PYELFTOOLS_AVAILABLE:
            print("Error: pyelftools library is not installed. This plugin cannot operate.")
            return False

        options = options or {}
        payload_file = options.get("payload_file")
        section_name = options.get("section_name", ".injected")
        make_executable = options.get("executable", False)

        if not payload_file:
            print("Error: 'payload_file' option is required.")
            return False
        if not os.path.exists(payload_file):
            print(f"Error: Payload file '{payload_file}' not found.")
            return False

        if not os.path.exists(binary_path):
            print(f"Error: Input binary '{binary_path}' not found.")
            return False

        try:
            with open(payload_file, 'rb') as pf:
                payload_data = pf.read()
        except Exception as e:
            print(f"Error reading payload file '{payload_file}': {e}")
            return False

        if not payload_data:
            print(f"Warning: Payload file '{payload_file}' is empty.")
            # Continue, as injecting an empty section might be a valid (though unusual) use case.

        # This method will be significantly rewritten to manually construct the modified ELF.
        # It's a complex operation. We will read the original ELF, then write a new
        # ELF to output_path incorporating the new section.

        print(f"Starting ELF section injection: '{binary_path}' -> '{output_path}' with payload '{payload_file}'")

        try:
            with open(binary_path, 'rb') as f_in:
                original_elf_data = bytearray(f_in.read()) # Use bytearray for easier manipulation if needed later

            elf_file = ELFFile(open(binary_path, 'rb')) # pyelftools ELFFile for reading structure

            # Architecture (32-bit or 64-bit)
            is_64bit = elf_file.elfclass == 64
            elf_header_cls = elf_file.structs.Elf_Ehdr
            section_header_cls = elf_file.structs.Elf_Shdr
            program_header_cls = elf_file.structs.Elf_Phdr

            # 1. Prepare payload and new section name
            with open(payload_file, 'rb') as pf:
                payload_bytes = pf.read()

            new_section_name_bytes = section_name.encode('ascii') + b'\x00' # Null-terminated

            # 2. Get existing .shstrtab (section header string table)
            shstrtab_scn = elf_file.get_section(elf_file.header['e_shstrndx'])
            if not shstrtab_scn:
                print("Error: .shstrtab not found.")
                return False
            original_shstrtab_data = bytearray(shstrtab_scn.data())

            # New .shstrtab data: old + new section name
            new_shstrtab_data = original_shstrtab_data + new_section_name_bytes
            sh_name_offset_in_new_shstrtab = len(original_shstrtab_data)


            # All modifications will be written to a new bytearray representing the new ELF file.
            modified_elf_data = bytearray()

            # Original ELF header
            ehdr = elf_file.header

            # Calculate offsets and sizes for new structures
            # We append everything new to the end of the original file content for simplicity.
            original_file_size = len(original_elf_data)

            # New section data will be placed after original content
            new_section_data_offset = original_file_size
            new_section_data_size = len(payload_bytes)

            # New .shstrtab data will be placed after new section data
            new_shstrtab_offset = new_section_data_offset + new_section_data_size
            new_shstrtab_size = len(new_shstrtab_data)

            # New section header for the injected section will be appended to the SHT
            # The SHT itself will be moved to after the new .shstrtab data
            new_sht_offset = new_shstrtab_offset + new_shstrtab_size

            # Create the new section header entry for our injected section
            # This needs to be constructed according to the ELF structs format
            # For now, this is a placeholder of what needs to be built
            # We will use elf_file.structs.Elf_Shdr.build()

            # Values for the new section header
            new_shdr_dict = {
                'sh_name': sh_name_offset_in_new_shstrtab, # Offset in the *new* shstrtab
                'sh_type': 'SHT_PROGBITS', # Standard type for code/data
                'sh_flags': 0x2, # SHF_ALLOC (Dynamically allocated during execution)
                                 # Potentially add SHF_WRITE (0x1), SHF_EXECINSTR (0x4)
                'sh_addr': 0,    # Virtual address. If loaded by PT_LOAD, this will be set by loader.
                                 # For simplicity, keep 0. A real packer might calculate this.
                'sh_offset': new_section_data_offset, # File offset of section data
                'sh_size': new_section_data_size,
                'sh_link': 0,
                'sh_info': 0,
                'sh_addralign': 4, # Typical alignment (e.g., 1, 4, 8, 16)
                'sh_entsize': 0    # Entry size, if section holds a table of fixed-size entries
            }
            if make_executable:
                new_shdr_dict['sh_flags'] |= 0x4 # SHF_EXECINSTR
                new_shdr_dict['sh_addralign'] = 16 # Executable sections often have higher alignment

            # --- Program Header Table (PHT) Modification for Executable Sections ---
            # If 'make_executable' is true, we need to add or modify a PT_LOAD segment.
            # This is a complex part. The goal is to find or create a PT_LOAD segment
            # that covers the memory where our new section will be loaded.

            new_phdr_entry_bytes = None
            modified_program_headers_data = original_elf_data[ehdr['e_phoff']:ehdr['e_phoff'] + ehdr['e_phentsize'] * ehdr['e_phnum']]

            # Determine the virtual address for the new section.
            # This is often aligned to page size (e.g., 0x1000 for 4KB pages).
            # Find the last PT_LOAD segment to determine a possible next available virtual address.
            new_section_vaddr = 0
            page_size = 0x1000 # Common page size

            last_load_phdr_vaddr = 0
            last_load_phdr_memsz = 0

            for i in range(ehdr['e_phnum']):
                phdr = elf_file.get_segment(i).header
                if phdr.p_type == 'PT_LOAD':
                    current_segment_end_vaddr = phdr.p_vaddr + phdr.p_memsz
                    if current_segment_end_vaddr > last_load_phdr_vaddr + last_load_phdr_memsz: # Simplistic check
                        last_load_phdr_vaddr = phdr.p_vaddr
                        last_load_phdr_memsz = phdr.p_memsz

            if last_load_phdr_vaddr + last_load_phdr_memsz > 0 :
                new_section_vaddr = (last_load_phdr_vaddr + last_load_phdr_memsz + page_size -1) & ~(page_size - 1)
            else: # No PT_LOAD segments found, or first one. This case needs more robust handling.
                  # For executables, there's usually at least one.
                  # A common base for PIE executables might be 0x0 and let loader decide,
                  # or for non-PIE, a fixed address like 0x400000 or 0x08048000.
                  # For simplicity, if no PT_LOAD, try to put it after where SHT will end in file.
                  # This is not correct for VAddr, which is memory.
                  # A default for PIE could be 0, relying on loader to place it.
                  # Let's assume a simple PIE-like behavior or high address for non-PIE if no other PT_LOADs.
                  # This needs to be more robust. For now, if no prior PT_LOAD, this will be problematic.
                  # A common practice for adding segments is to ensure it's page aligned.
                  # Picking a VAddr is hard without knowing more about the binary (PIE, etc.)
                  # Let's set a placeholder, this will likely need adjustment.
                  # A simple executable might start its first PT_LOAD at e.g. ehdr.e_entry & ~(page_size-1) or a fixed base.
                  # For now, if no previous PT_LOAD, we'll set it to a conventional 0x200000 + original_file_size aligned,
                  # which is arbitrary and likely wrong for many cases.
                if ehdr['e_type'] == 'ET_EXEC' and not (ehdr['e_flags'] & 0x4): # Non-PIE executable (EF_PIC is 0x2, but e_flags is not standard for this)
                                                                            # A better check for PIE is if e_type is ET_DYN and has PT_INTERP
                    new_section_vaddr = 0x08048000 + original_file_size # Example for 32-bit non-PIE
                    if is_64bit:
                         new_section_vaddr = 0x400000 + original_file_size # Example for 64-bit non-PIE
                    new_section_vaddr = (new_section_vaddr + page_size -1) & ~(page_size -1)

                else: # ET_DYN (shared lib or PIE executable)
                    new_section_vaddr = ( (last_load_phdr_vaddr + last_load_phdr_memsz if (last_load_phdr_vaddr + last_load_phdr_memsz) > 0 else 0x200000 ) # Arbitrary base if no PT_LOADs
                                     + new_section_data_size + page_size -1) & ~(page_size -1)


            if make_executable:
                new_shdr_dict['sh_addr'] = new_section_vaddr # Set virtual address for the section

                # Create a new PT_LOAD segment for the injected code
                # This new PHDR will be appended to the existing PHDR table in the file
                new_phdr_dict = {
                    'p_type': 'PT_LOAD',
                    'p_flags': 0x5,  # PF_R | PF_X (Read, Execute)
                    'p_offset': new_section_data_offset, # File offset of the new section data
                    'p_vaddr': new_section_vaddr,        # Virtual address
                    'p_paddr': new_section_vaddr,        # Physical address (usually same as vaddr on modern OS)
                    'p_filesz': new_section_data_size,   # Size in file
                    'p_memsz': new_section_data_size,    # Size in memory (can be larger for .bss)
                    'p_align': page_size                 # Alignment (e.g., 0x1000 or 0x200000 for segments)
                }
                new_phdr_entry_bytes = program_header_cls.build(new_phdr_dict)

                # The PHT is usually right after the ELF header. Appending a new PHDR entry means
                # shifting all subsequent file content (all sections). This is very complex.
                # A common "trick" is to find a PT_NOTE segment and overwrite it if it's unused and large enough.
                # Or, if there's padding after PHT.
                # For this version, we'll attempt to place the *new PHT itself* (original + new entry)
                # at the end of the file, similar to SHT. This is non-standard but simpler than shifting.
                # Or, more correctly, the PHT must be contiguous. So we'd read original PHT, append new entry,
                # then write this new PHT block. This requires finding space.
                # The simplest for now (but still potentially problematic) is to assume PHT is at e_phoff
                # and we are *adding* an entry, so e_phnum increases.
                # If we append to the PHT, we need space *at its original location*.
                # This is the hardest part of "simple" injection.
                #
                # Alternative: Place the new PHDR table after the ELF header, if there's space
                # before the first section's data begins. This means e_phoff would be fixed,
                # but we need to ensure no overlap.
                #
                # For now, let's assume we will *not* move the PHT but try to append to it if there's space,
                # or accept that this part is highly experimental.
                # A truly robust solution here often involves re-laying out the ELF or using specific techniques
                # like the PT_NOTE to PT_LOAD conversion or finding code caves within existing segments.

                # Let's assume for this simplified version that we will append the new PHDR entry
                # to the existing block of PHDRs, and this block is at ehdr.e_phoff.
                # This means data after original PHT needs to be shifted IF PHT is not the last header block.
                # This is where it gets very tricky.
                # A simpler (but non-standard for SHT) approach taken for SHT was to move it to EOF.
                # PHT is more constrained by loaders.
                # For this iteration, I will *not* implement shifting. I will attempt to append
                # the new phdr to the program_headers_data and update e_phnum.
                # This will only work if there's implicit padding or if the loader is lenient.
                # This part is highly likely to break binaries without careful handling of file layout.
                print("WARNING: Program Header Table (PHT) modification for executable sections is highly experimental.")
                print("         The current method of appending a new PHDR might not produce a runnable binary")
                print("         without proper relocation of subsequent file content or finding existing space/PT_NOTE.")

                # We will append the new PHDR to the existing list of PHDRs data.
                # This means the file needs to be reconstructed to insert this.
                # The easiest way is to write:
                # 1. Modified ELF Header (e_phnum++, e_phoff potentially changed if we moved PHT)
                # 2. Concatenated PHT data (original_phdrs + new_phdr_entry_bytes)
                # 3. All other data shifted accordingly.
                # THIS IS THE COMPLEX SHIFTING.
                #
                # Let's simplify: Assume the original PHT has some padding after it,
                # or we're okay with a potentially broken ELF for this stage if it doesn't.
                # We will write the new PHDR entry right after the old ones.
                # This would mean that `modified_program_headers_data` needs to be original + new.
                # And `e_phoff` in ELF header remains the same, but `e_phnum` increases.
                # The data that was originally after PHT must now be after the *extended* PHT.

                # To avoid shifting everything for now:
                # The new PHDR data is `new_phdr_entry_bytes`.
                # The original PHT data is `program_headers_data`.
                # The new PHT will be `program_headers_data + new_phdr_entry_bytes`.
                # This means the file size increases by `ehdr.e_phentsize`.
                # All offsets *after* the PHT in the original file need to be incremented by `ehdr.e_phentsize`.
                # This includes section data offsets (sh_offset in SHT) and e_shoff in ELF header.

                # This is becoming too complex for a quick implementation.
                # Let's stick to the "append everything new at the end" strategy for now,
                # and acknowledge PT_LOAD for executable sections is the main challenge.
                # The new section header (new_shdr_dict) already has sh_addr set.
                # The PT_LOAD segment, if we could add it, would map this.

                # For now, we will *not* modify the PHT in this pass.
                # The section will be marked executable in SHT, but no new PT_LOAD segment.
                # This means the OS loader will not map it as executable.
                # This is a known limitation I'll address if possible or document.
                if new_phdr_entry_bytes: # If we had built it
                     print("PT_LOAD segment prepared but PHT modification strategy is pending robust implementation.")
                     # For now, don't use it.
                     new_phdr_entry_bytes = None # Disable PHT modification for this iteration.


            # Build the new section header entry (now potentially with sh_addr)
            new_section_header_entry_bytes = section_header_cls.build(new_shdr_dict)

            # --- Reconstruct the ELF file ---
            modified_ehdr_dict = dict(ehdr)
            modified_ehdr_dict['e_shoff'] = new_sht_offset
            modified_ehdr_dict['e_shnum'] = ehdr['e_shnum'] + 1

            if new_phdr_entry_bytes: # If we were to add a PHDR
                # This part is tricky as it implies shifting or finding space for PHT
                # modified_ehdr_dict['e_phnum'] = ehdr['e_phnum'] + 1
                # And all sh_offset and e_shoff might need to be shifted if PHT grows in place.
                # For now, this path is effectively disabled by new_phdr_entry_bytes being None.
                pass


            original_shstrtab_sh_idx = ehdr['e_shstrndx']

            # Build new SHT
            new_sht_entries_data = bytearray()
            for i in range(ehdr['e_shnum']):
                scn = elf_file.get_section(i)
                current_shdr_dict = dict(scn.header)
                if i == original_shstrtab_sh_idx:
                    current_shdr_dict['sh_offset'] = new_shstrtab_offset
                    current_shdr_dict['sh_size'] = new_shstrtab_size
                new_sht_entries_data.extend(section_header_cls.build(current_shdr_dict))
            new_sht_entries_data.extend(new_section_header_entry_bytes)

            final_ehdr_bytes = elf_header_cls.build(modified_ehdr_dict)

            # Get original PHT data (unchanged for now)
            # If new_phdr_entry_bytes was active, this would be original PHT + new PHDR entry.
            current_program_headers_data = original_elf_data[ehdr['e_phoff']:ehdr['e_phoff'] + ehdr['e_phentsize'] * ehdr['e_phnum']]
            # If we were adding a PHDR entry, and NOT shifting the file:
            # current_program_headers_data would need to be written contiguously with new_phdr_entry_bytes,
            # which implies having space at ehdr.e_phoff + ehdr.e_phentsize * ehdr.e_phnum.

            with open(output_path, 'wb') as f_out_final:
                f_out_final.write(original_elf_data)

                f_out_final.seek(0)
                f_out_final.write(final_ehdr_bytes)

                # If PHT was modified (e.g. e_phnum changed), we'd rewrite it here.
                # For now, original PHT is preserved from the initial full write.
                # If new_phdr_entry_bytes was to be used, it implies complex file restructuring
                # or finding a specific spot (like overwriting PT_NOTE).
                # This simplified version does not yet do that.

                f_out_final.seek(new_section_data_offset)
                f_out_final.write(payload_bytes)

                f_out_final.seek(new_shstrtab_offset)
                f_out_final.write(new_shstrtab_data)

                f_out_final.seek(new_sht_offset)
                f_out_final.write(new_sht_entries_data)

            print(f"ELF Section Injector: Attempted to inject payload from '{payload_file}' into '{output_path}' as section '{section_name}'.")
            print("WARNING: This manual ELF modification is EXPERIMENTAL.")
            if make_executable:
                print("Executable section flag set. However, Program Header (PT_LOAD segment) modification is CRUCIAL for execution and NOT YET robustly implemented.")
                print("The OS loader might not map this section as executable without a corresponding PT_LOAD segment.")
            print("Validate with 'readelf -h -S -l output_path'.")

            return True

        except FileNotFoundError:
            print(f"Error: File not found (input: '{binary_path}' or payload: '{payload_file}').")
            return False
        except Exception as e:
            print(f"Error during ELF section injection: {e}")
            import traceback
            traceback.print_exc()
            if os.path.exists(output_path) and output_path != binary_path:
                try: os.remove(output_path)
                except OSError: pass
            return False

import subprocess # For running readelf
import tempfile

# Helper function to run readelf and parse section info (simplified)
def get_section_info_from_readelf(elf_path: str, section_name: str) -> dict | None:
    if not shutil.which("readelf"):
        print("readelf command not found, skipping readelf verification.")
        return None
    try:
        # readelf -S -W <elf_path>  (-W for wide output, helps with parsing)
        result = subprocess.run(["readelf", "-S", "-W", elf_path], capture_output=True, text=True, check=True)

        # Parse output to find the section
        # This is a simplified parser, real readelf output is complex
        lines = result.stdout.splitlines()
        header_skipped = False
        idx_name, idx_type, idx_addr, idx_off, idx_size, idx_flags, idx_align = -1,-1,-1,-1,-1,-1,-1

        for line in lines:
            if not header_skipped: # Skip initial lines until header like "[Nr] Name..."
                if "Name" in line and "Type" in line and "Address" in line: # Brittle header check
                    # Try to map columns based on known header names
                    # Example: [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
                    # This parsing is very basic and might break with different readelf versions or locales.
                    # A more robust parser would use fixed-width or more intelligent splitting.
                    # For now, simple string searching for column headers:
                    # This is still very fragile.
                    # A better way might be to look for line starting with `[ <number>] section_name`
                    # and then parse that line.

                    # Let's find the line for our section by name first.
                    pass # Header parsing logic is complex and error prone.
                continue # Skip until we are past the column headers.

            # A typical section line looks like:
            # [ 4] .dynsym           DYNSYM          00000000000002c8 0002c8 0001b0 18   A  5   1  8
            # We are looking for `section_name`
            if section_name in line:
                parts = line.split() # Simplistic split
                # Expected format around name: `[<idx>] <name> <TYPE> <Addr> <Off> <Size> ... <Flg>`
                # This needs very careful parsing. Example:
                # [16] .mydata           PROGBITS        0000000000000000 0040f0 00001c 00  WA  0   0  4
                # [17] .mycode           PROGBITS        0000000000205000 00410c 00001c 00  AX  0   0 16

                # Attempt to find fields based on common positioning relative to name
                try:
                    name_idx_in_parts = -1
                    for i, p in enumerate(parts):
                        if p == section_name:
                            name_idx_in_parts = i
                            break
                    if name_idx_in_parts == -1: continue

                    # Assuming a structure like: [<num>] name type address offset size es flags ...
                    # This is extremely brittle parsing.
                    s_info = {
                        "name": parts[name_idx_in_parts],
                        "type": parts[name_idx_in_parts + 1],
                        "address": parts[name_idx_in_parts + 2],
                        "offset": parts[name_idx_in_parts + 3],
                        "size": parts[name_idx_in_parts + 4],
                        # Flags are usually near the end or after ES, Lk, Inf
                        # Example flags: "WA", "AX"
                        "flags": "" # To be populated by searching common flag chars
                    }
                    # Try to find flags like 'A' (ALLOC), 'X' (EXECINSTR), 'W' (WRITE)
                    # These flags are usually in a single string like "WA", "AX", "A"
                    # Search for the flags string, typically after ES, Lk, Inf columns
                    # This is still an approximation.
                    # Let's assume flags are in parts[name_idx_in_parts + 6] or similar if ES is 00
                    # or parts[name_idx_in_parts + 8] if ES, Lk, Inf are present.
                    # This is too fragile. A regex might be better.
                    # For now, we'll just check if 'A', 'X' appear in the line after size.

                    flags_part_candidate = ""
                    # Try to find the flags string (e.g., "WAX", "A", "AX")
                    # It's usually a short string of capital letters.
                    # The flags field is typically after 'ES', 'Lk', 'Inf', 'Al'
                    # Look for a field consisting of capital letters (A, W, X, M, S, I, L, O, G, T, C, E, p)
                    # Example: [12] .text             PROGBITS        00000000000006b0 0006b0 000215 00  AX  0   0 16
                    # The 'AX' is what we want.
                    potential_flags_indices = []
                    if len(parts) > name_idx_in_parts + 5: # Ensure enough parts exist
                        # Iterate through parts after 'size' to find flag-like string
                        for i in range(name_idx_in_parts + 5, len(parts)):
                            if parts[i].isalpha() and parts[i].isupper():
                                s_info["flags"] = parts[i]
                                break
                    return s_info
                except IndexError:
                    # Failed to parse this line
                    continue
        return None # Section not found or parsing failed
    except subprocess.CalledProcessError as e:
        print(f"readelf failed: {e.stderr}")
        return None
    except Exception as e:
        print(f"Error parsing readelf output: {e}")
        return None

if __name__ == '__main__':
    if not PYELFTOOLS_AVAILABLE:
        print("Skipping ElfSectionInjectorPlugin direct test: pyelftools not installed.")
    else:
        plugin = ElfSectionInjectorPlugin()
        test_dir = "temp_test_injector"
        os.makedirs(test_dir, exist_ok=True)

        # Create a simple base ELF file to inject into.
        # Compiling a minimal C program is best.
        source_c_file = os.path.join(test_dir, "base_app.c")
        base_elf_file = os.path.join(test_dir, "base_app.elf")
        with open(source_c_file, "w") as f:
            f.write("int main() { return 0; }")

        import platform
        arch_flag = "-m64" if platform.machine() == "x86_64" else "-m32"
        # Use -static for simpler ELF structure if possible, though not strictly necessary.
        # Using -fPIE -pie for position-independent executable, common for modern systems.
        compile_cmd = ["gcc", arch_flag, "-fPIE", "-pie", source_c_file, "-o", base_elf_file]
        print(f"Compiling base ELF: {' '.join(compile_cmd)}")
        compile_proc = subprocess.run(compile_cmd, capture_output=True)
        if compile_proc.returncode != 0:
            print(f"Failed to compile base_app.c. Aborting tests.")
            print(f"GCC STDOUT: {compile_proc.stdout.decode(errors='ignore')}")
            print(f"GCC STDERR: {compile_proc.stderr.decode(errors='ignore')}")
            shutil.rmtree(test_dir, ignore_errors=True)
            exit(1)

        print(f"Base ELF '{base_elf_file}' compiled successfully.")

        # Test 1: Inject a data section
        print("\n--- Test 1: Injecting a DATA section ---")
        payload_data_content = b"This is my injected data payload!" * 10
        payload_data_file = os.path.join(test_dir, "payload_data.bin")
        with open(payload_data_file, "wb") as f:
            f.write(payload_data_content)

        output_elf_data_injection = os.path.join(test_dir, "app_data_injected.elf")
        data_section_name = ".mydata"
        options_data = {
            "payload_file": payload_data_file,
            "section_name": data_section_name,
            "executable": False
        }
        success_data = plugin.obfuscate(base_elf_file, output_elf_data_injection, options=options_data)
        assert success_data, "Data section injection failed."
        print(f"Data section injection reported success. Output: {output_elf_data_injection}")

        if success_data and os.path.exists(output_elf_data_injection):
            info = get_section_info_from_readelf(output_elf_data_injection, data_section_name)
            assert info is not None, f"Failed to get section info for {data_section_name} using readelf."
            print(f"Readelf info for {data_section_name}: {info}")
            assert info["name"] == data_section_name
            assert info["type"] == "PROGBITS" # Standard for data/code
            # Check flags: 'A' for ALLOC. Might also have 'W' for WRITABLE.
            # The current injector sets sh_flags = 0x2 (SHF_ALLOC) for non-exec,
            # which readelf might show as just 'A'. If writable (SHF_WRITE=0x1), it'd be 'WA'.
            # Current flags are just SHF_ALLOC (0x2). Let's check for 'A'.
            assert "A" in info["flags"], f"Expected ALLOC flag for {data_section_name}"
            assert "X" not in info["flags"], f"Did not expect EXECINSTR flag for {data_section_name}"
            # Size check (in hex from readelf output)
            expected_size_hex = hex(len(payload_data_content))[2:] # e.g., "1c" for 28 bytes
            # Pad with leading zeros if needed to match readelf output format (e.g., 00001c)
            assert expected_size_hex in info["size"].lower(), \
                   f"Size mismatch for {data_section_name}. Expected hex ~{expected_size_hex}, got {info['size']}"
            print(f"Data section '{data_section_name}' verified with readelf.")


        # Test 2: Inject an executable section (metadata check)
        print("\n--- Test 2: Injecting an EXECUTABLE section (metadata check) ---")
        payload_code_content = b"\x90\x90\x90\x90" # Some NOPs
        payload_code_file = os.path.join(test_dir, "payload_code.bin")
        with open(payload_code_file, "wb") as f:
            f.write(payload_code_content)

        output_elf_code_injection = os.path.join(test_dir, "app_code_injected.elf")
        code_section_name = ".mycode"
        options_code = {
            "payload_file": payload_code_file,
            "section_name": code_section_name,
            "executable": True
        }
        success_code = plugin.obfuscate(base_elf_file, output_elf_code_injection, options=options_code)
        assert success_code, "Executable section injection failed."
        print(f"Executable section injection reported success. Output: {output_elf_code_injection}")

        if success_code and os.path.exists(output_elf_code_injection):
            info = get_section_info_from_readelf(output_elf_code_injection, code_section_name)
            assert info is not None, f"Failed to get section info for {code_section_name} using readelf."
            print(f"Readelf info for {code_section_name}: {info}")
            assert info["name"] == code_section_name
            assert info["type"] == "PROGBITS"
            # Flags should include 'A' (ALLOC) and 'X' (EXECINSTR).
            assert "A" in info["flags"], f"Expected ALLOC flag for {code_section_name}"
            assert "X" in info["flags"], f"Expected EXECINSTR flag for {code_section_name}"
            # Check sh_addr (Address column from readelf)
            assert int(info["address"], 16) != 0, f"Expected non-zero sh_addr for executable section {code_section_name}"
            print(f"Executable section '{code_section_name}' metadata verified with readelf.")

            # Verify Program Headers (expect no new PT_LOAD for now)
            if shutil.which("readelf"):
                phdr_result = subprocess.run(["readelf", "-l", "-W", output_elf_code_injection], capture_output=True, text=True, check=True)
                # This is a negative test for now: ensure our .mycode section's vaddr is NOT covered by a PT_LOAD segment
                # because we haven't implemented PHT modification yet.
                # This test will need to change if PHT mod is added.
                # The vaddr of .mycode is info["address"]
                target_vaddr = int(info["address"], 16)
                target_size = int(info["size"], 16) # Size of .mycode section

                found_in_pt_load = False
                for line in phdr_result.stdout.splitlines():
                    if "LOAD" in line:
                        # Example PT_LOAD line:
                        #  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000 0x000668 0x000668 R E 0x200000
                        #  LOAD           0x0000000000000da0 0x0000000000600da0 0x0000000000600da0 0x000278 0x000280 RW  0x200000
                        # We need Vaddr and MemSiz from this line.
                        phdr_parts = line.split()
                        try:
                            # Assuming Vaddr is 3rd field (0-indexed), MemSiz is 6th or 7th (after FileSiz)
                            # This parsing is very fragile.
                            idx_type = phdr_parts.index("LOAD") if "LOAD" in phdr_parts else -1
                            if idx_type == -1 or len(phdr_parts) < idx_type + 7: continue

                            phdr_vaddr = int(phdr_parts[idx_type + 2], 16) # Vaddr field
                            phdr_memsz = int(phdr_parts[idx_type + 6], 16) # MemSiz field (careful with FileSiz vs MemSiz position)
                                                                        # Usually: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flags Align
                            if target_vaddr >= phdr_vaddr and (target_vaddr + target_size) <= (phdr_vaddr + phdr_memsz):
                                found_in_pt_load = True
                                break
                        except (ValueError, IndexError):
                            continue # Parsing this line failed

                assert not found_in_pt_load, \
                    f"Executable section {code_section_name} (vaddr 0x{target_vaddr:x}) " \
                    "UNEXPECTEDLY found within a PT_LOAD segment. PHT modification test needs update."
                print("Program Header Table check: As expected, no new PT_LOAD segment covers the injected executable section (known limitation).")
            else:
                print("Skipping readelf -l check as readelf is not available.")


        # Cleanup
        # shutil.rmtree(test_dir, ignore_errors=True)
        print(f"\nTest files are in '{test_dir}'. Clean up manually if desired.")
        print(f"{plugin.get_name()} self-tests complete.")

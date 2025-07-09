import zlib
import os
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

class BasicCompressorPlugin(ObfuscationPlugin):
    """
    A simple plugin that compresses the entire input file using zlib.
    This is a placeholder for a more advanced UPX-style compressor.
    """
    def get_name(self) -> str:
        return "basic_compressor"

    def get_description(self) -> str:
        return "Compresses the input file using zlib. Output is not self-extracting."

    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        """
        Compresses the input binary file and saves it to output_path.

        Args:
            binary_path: Path to the input binary file.
            output_path: Path to save the compressed file.
            options: A dictionary of plugin-specific options.
                     - "level": Zlib compression level (0-9). Default: 6.

        Returns:
            True if compression was successful, False otherwise.
        """
        options = options or {}
        compression_level = options.get("level", 6)
        if not (0 <= compression_level <= 9):
            print(f"Error: Invalid compression level {compression_level}. Must be between 0 and 9.")
            return False

        try:
            with open(binary_path, 'rb') as f_in:
                original_data = f_in.read()

            compressed_data = zlib.compress(original_data, level=compression_level)

            with open(output_path, 'wb') as f_out:
                f_out.write(compressed_data)

            original_size = len(original_data)
            compressed_size = len(compressed_data)
            print(f"BasicCompressor: Compressed '{binary_path}' from {original_size} bytes to {compressed_size} bytes (level {compression_level}). Saved to '{output_path}'.")
            if compressed_size >= original_size:
                print("Warning: Compressed size is not smaller than original size.")

            return True
        except FileNotFoundError:
            print(f"Error: Input file '{binary_path}' not found.")
            return False
        except Exception as e:
            print(f"Error during compression: {e}")
            return False

    def get_options_schema(self) -> dict:
        return {
            "level": {
                "type": "integer",
                "description": "Zlib compression level (0-9). Higher is more compression but slower.",
                "default": 6,
                "required": False
            }
        }

if __name__ == '__main__':
    # Example usage for testing this plugin directly
    plugin = BasicCompressorPlugin()

    # Create a dummy input file
    dummy_input_file = "dummy_input.bin"
    dummy_output_file = "dummy_output.zlib"
    with open(dummy_input_file, "wb") as f:
        f.write(os.urandom(1024 * 10)) # 10KB of random data for testing compression

    print(f"Testing {plugin.get_name()}:")
    print(f"Description: {plugin.get_description()}")
    print(f"Options schema: {plugin.get_options_schema()}")

    success = plugin.obfuscate(dummy_input_file, dummy_output_file, options={"level": 9})
    print(f"Obfuscation successful: {success}")

    if success:
        original_size = os.path.getsize(dummy_input_file)
        compressed_size = os.path.getsize(dummy_output_file)
        print(f"Original size: {original_size}, Compressed size: {compressed_size}")
        assert compressed_size < original_size, "Compression should reduce size for random data"
        os.remove(dummy_output_file)

    # Test with default compression level
    success_default = plugin.obfuscate(dummy_input_file, dummy_output_file)
    print(f"Obfuscation with default level successful: {success_default}")
    if success_default:
        os.remove(dummy_output_file)

    # Test invalid level
    success_invalid = plugin.obfuscate(dummy_input_file, dummy_output_file, options={"level": 10})
    print(f"Obfuscation with invalid level successful (should be False): {not success_invalid}")
    assert not success_invalid

    # Test file not found
    success_notfound = plugin.obfuscate("nonexistent.bin", "output.zlib")
    print(f"Obfuscation with non-existent file successful (should be False): {not success_notfound}")
    assert not success_notfound

    os.remove(dummy_input_file)
    print(f"{plugin.get_name()} test complete.")

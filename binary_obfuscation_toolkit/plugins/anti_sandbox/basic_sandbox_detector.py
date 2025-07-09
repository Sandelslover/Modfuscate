import os
import getpass
import socket
import time
import psutil # For process, disk, RAM checks. Needs to be added to requirements.txt
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

# Conceptual C code snippets for what might be injected into a binary:
# These are for illustration only.

C_USERNAME_CHECK_SNIPPET = """
#include <unistd.h>
#include <string.h>
#include <stdio.h> // For sandbox use, not malware

int check_username() {
    char* user = getlogin();
    if (user == NULL) return 0; // Could be suspicious itself

    const char* common_sandbox_users[] = {"sandbox", "test", "maltest", "vagrant", "docker", "user", "admin", "currentuser"};
    for (int i = 0; i < sizeof(common_sandbox_users) / sizeof(char*); ++i) {
        if (strcmp(user, common_sandbox_users[i]) == 0) {
            // printf("Sandbox username detected: %s\\n", user);
            return 1; // Detected
        }
    }
    return 0; // Not detected
}
"""

C_HOSTNAME_CHECK_SNIPPET = """
#include <unistd.h>
#include <string.h>
#include <stdio.h> // For sandbox use

int check_hostname() {
    char hostname[1024];
    hostname[1023] = '\\0';
    gethostname(hostname, 1023);

    const char* common_sandbox_hosts[] = {"sandbox", "test-pc", "vm", "virtual", "analysis"};
    for (int i = 0; i < sizeof(common_sandbox_hosts) / sizeof(char*); ++i) {
        if (strstr(hostname, common_sandbox_hosts[i]) != NULL) { // Use strstr for partial matches
            // printf("Sandbox hostname detected: %s\\n", hostname);
            return 1; // Detected
        }
    }
    return 0; // Not detected
}
"""

C_SLEEP_ACCELERATION_CHECK_SNIPPET = """
#include <time.h>
#include <unistd.h> // for sleep
#include <stdio.h>  // for printf

int check_sleep_acceleration() {
    time_t start_time, end_time;
    unsigned int sleep_duration = 5; // seconds

    time(&start_time);
    sleep(sleep_duration); // In a real binary, use syscall or platform API
    time(&end_time);

    double time_elapsed = difftime(end_time, start_time);
    // printf("Requested sleep: %u, Actual time elapsed: %f\\n", sleep_duration, time_elapsed);

    // If time elapsed is significantly less than requested, it might be accelerated.
    // Threshold should be less than sleep_duration, e.g., sleep_duration * 0.5
    if (time_elapsed < (double)sleep_duration * 0.75) {
        // printf("Potential sleep acceleration detected.\\n");
        return 1; // Detected
    }
    return 0; // Not detected
}
"""

class BasicSandboxDetectorPlugin(ObfuscationPlugin):
    """
    A conceptual plugin that uses Python checks to simulate anti-sandbox techniques.
    It does NOT modify the binary itself in this version. It reports findings.
    """

    def get_name(self) -> str:
        return "basic_sandbox_detector"

    def get_description(self) -> str:
        return "Simulates basic anti-sandbox checks (does not modify binary). Reports if sandbox-like traits are found."

    def get_options_schema(self) -> dict:
        return {
            "check_username": {
                "type": "boolean",
                "description": "Enable username check.",
                "default": True,
                "required": False
            },
            "check_hostname": {
                "type": "boolean",
                "description": "Enable hostname check.",
                "default": True,
                "required": False
            },
            "check_sleep": {
                "type": "boolean",
                "description": "Enable sleep acceleration check.",
                "default": True,
                "required": False
            },
            "sleep_duration_sec": {
                "type": "integer",
                "description": "Duration for sleep check in seconds.",
                "default": 3,
                "required": False
            },
            "check_disk_size": {
                "type": "boolean",
                "description": "Enable disk size check.",
                "default": True,
                "required": False
            },
            "min_disk_gb": {
                "type": "integer",
                "description": "Minimum disk size in GB to not be considered a sandbox.",
                "default": 50, # Typical sandboxes might have < 50GB
                "required": False
            }
        }

    def _check_username(self) -> (bool, str):
        try:
            user = getpass.getuser()
            common_sandbox_users = ["sandbox", "test", "maltest", "vagrant", "docker", "user", "admin", "currentuser", "vmware", "virtualbox", "qemu", "hyperv"]
            if user.lower() in common_sandbox_users:
                return True, f"Suspicious username detected: {user}"
        except Exception as e:
            return False, f"Username check failed: {e}"
        return False, "Username appears normal."

    def _check_hostname(self) -> (bool, str):
        try:
            hostname = socket.gethostname().lower()
            common_sandbox_host_patterns = ["sandbox", "test-pc", "vm-", "virtual", "analysis", "malware", "lab", "desktop-"] # desktop- might be too generic
            for pattern in common_sandbox_host_patterns:
                if pattern in hostname:
                    return True, f"Suspicious hostname detected: {hostname} (matches '{pattern}')"
        except Exception as e:
            return False, f"Hostname check failed: {e}"
        return False, "Hostname appears normal."

    def _check_sleep_acceleration(self, duration_sec: int) -> (bool, str):
        try:
            start_time = time.monotonic()
            time.sleep(duration_sec) # Python's time.sleep can also be hooked/accelerated
            end_time = time.monotonic()
            elapsed_time = end_time - start_time

            # If elapsed time is less than, say, 75% of requested, flag it.
            if elapsed_time < float(duration_sec) * 0.75:
                return True, f"Potential sleep acceleration: requested {duration_sec}s, elapsed {elapsed_time:.2f}s"
        except Exception as e:
            return False, f"Sleep check failed: {e}"
        return False, f"Sleep duration ({elapsed_time:.2f}s for {duration_sec}s) appears normal."

    def _check_disk_size(self, min_disk_gb: int) -> (bool, str):
        try:
            # Check root partition disk size. This might vary by OS.
            # psutil.disk_usage('/') works for Unix-like. For Windows, it's often 'C:\\'.
            # For simplicity, let's assume '/' for now.
            usage = psutil.disk_usage('/')
            total_gb = usage.total / (1024**3)
            if total_gb < min_disk_gb:
                return True, f"Low disk size detected: {total_gb:.2f}GB (threshold {min_disk_gb}GB)"
        except Exception as e:
            return False, f"Disk size check failed: {e}"
        return False, f"Disk size ({total_gb:.2f}GB) appears normal."


    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        """
        This plugin, in its current version, does not modify the binary.
        It runs checks on the environment where the toolkit is running
        and reports if it detects sandbox-like characteristics.
        A future version would inject code into the binary to perform these checks at runtime.
        """
        options = options or {}
        detections = []

        print(f"--- Running Basic Sandbox Detections (on host environment, not modifying '{binary_path}') ---")

        if options.get("check_username", True):
            detected, msg = self._check_username()
            if detected: detections.append(f"Username: {msg}")
            print(f"Username Check: {msg}")

        if options.get("check_hostname", True):
            detected, msg = self._check_hostname()
            if detected: detections.append(f"Hostname: {msg}")
            print(f"Hostname Check: {msg}")

        if options.get("check_sleep", True):
            duration = options.get("sleep_duration_sec", 3)
            detected, msg = self._check_sleep_acceleration(duration)
            if detected: detections.append(f"Sleep: {msg}")
            print(f"Sleep Acceleration Check: {msg}")

        if options.get("check_disk_size", True):
            min_gb = options.get("min_disk_gb", 50)
            detected, msg = self._check_disk_size(min_gb)
            if detected: detections.append(f"Disk Size: {msg}")
            print(f"Disk Size Check: {msg}")

        # Since we are not modifying the binary, we should not overwrite output_path
        # unless it's explicitly meant to be a report or a modified binary.
        # For now, we'll just indicate success if checks ran.
        # If binary_path is different from output_path, copy it to signify "processing"
        if binary_path != output_path:
            try:
                shutil.copy2(binary_path, output_path)
            except Exception as e:
                print(f"Error copying {binary_path} to {output_path}: {e}")
                return False # Failed to produce output

        if detections:
            print("\n--- Potential Sandbox Detections: ---")
            for detection in detections:
                print(f"- {detection}")
            print("Note: These detections are based on the environment where this toolkit is running.")
            # In a real scenario, the binary would be modified to perform these checks itself.
        else:
            print("\n--- No obvious sandbox characteristics detected by these basic checks. ---")

        # This plugin "succeeds" by running the checks.
        # The "obfuscation" is conceptual: if this were an actual binary modification,
        # it would now contain these checks.
        return True


if __name__ == '__main__':
    # This test runs in the environment where the script is executed.
    # So, results will vary based on your actual system.

    # First, check if psutil is available
    try:
        import psutil
    except ImportError:
        print("psutil library not found. Some checks in BasicSandboxDetectorPlugin will fail or be skipped.")
        print("Please install it: pip install psutil")
        # Decide if you want to exit or let the plugin handle the missing library.
        # For this test, we'll let the plugin's internal error handling (if any) manage it.
        # The current plugin code would raise an error if psutil calls fail.

    plugin = BasicSandboxDetectorPlugin()

    print(f"Testing {plugin.get_name()}:")
    print(f"Description: {plugin.get_description()}")
    print(f"Options schema: {plugin.get_options_schema()}")

    # Create dummy input and output paths
    dummy_input_file = "dummy_binary_for_antisandbox.bin"
    dummy_output_file = "dummy_binary_antisandbox_applied.bin" # Will be a copy
    with open(dummy_input_file, "wb") as f:
        f.write(b"Original binary content")

    # Run with default options
    print("\n--- Running with default options: ---")
    success = plugin.obfuscate(dummy_input_file, dummy_output_file)
    print(f"Plugin execution successful: {success}")

    # Run with specific options (e.g., disable one check)
    print("\n--- Running with sleep check disabled: ---")
    options_no_sleep = {"check_sleep": False}
    success_no_sleep = plugin.obfuscate(dummy_input_file, dummy_output_file, options=options_no_sleep)
    print(f"Plugin execution (no sleep check) successful: {success_no_sleep}")

    # Clean up
    if os.path.exists(dummy_input_file):
        os.remove(dummy_input_file)
    if os.path.exists(dummy_output_file):
        os.remove(dummy_output_file)

    print(f"\n{plugin.get_name()} test complete.")
    print("Note: The 'detections' depend on the environment this script is run in.")
    print("If you are on a development machine, it's unlikely to trigger 'sandbox' detections.")

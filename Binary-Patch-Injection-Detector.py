# -*- coding: utf-8 -*-
"""
Created on Mon Mar 3 8:10:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Binary Patch Injection Detector")
print(Fore.GREEN+font)

import os
import hashlib
import pefile

# Function to compute SHA256 hash of a file
def compute_file_hash(file_path):
    """Computes SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        # Read file in chunks
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to analyze PE file (Windows Executable)
def analyze_pe_file(file_path):
    """Analyze PE (Portable Executable) file and check for unusual modifications."""
    try:
        pe = pefile.PE(file_path)
        
        print(f"\nAnalyzing PE file: {file_path}")
        
        # Check for unusual code section modifications
        suspicious_sections = []
        for section in pe.sections:
            # Look for non-zero entropy or very large sections in unexpected places
            if section.SizeOfRawData > 100000:  # Large section might indicate injected code
                suspicious_sections.append(section)
        
        if suspicious_sections:
            print("Warning: Potential patch injection detected in the following sections:")
            for section in suspicious_sections:
                print(f"  - Section: {section.Name.decode().strip()}")
                print(f"    Size: {section.SizeOfRawData} bytes")
                print(f"    Virtual Address: {hex(section.VirtualAddress)}")
        else:
            print("No suspicious sections found in the PE file.")
        
        # Check for any unexpected imports (which could be indicative of injected code)
        suspicious_imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                # If the function name is not the expected one, it could be a sign of malicious modification
                if imp.name and len(imp.name) > 0:
                    suspicious_imports.append((entry.dll.decode(), imp.name.decode()))
        
        if suspicious_imports:
            print("\nSuspicious imports detected:")
            for dll, func in suspicious_imports:
                print(f"  - Library: {dll}, Function: {func}")
        else:
            print("\nNo suspicious imports detected.")
        
    except Exception as e:
        print(f"Error analyzing PE file: {e}")

# Function to check if the executable has been modified by comparing hashes
def check_for_patch(file_path, known_good_hash):
    """Compares the SHA256 hash of the file to the known good hash."""
    print("\nChecking file integrity...")
    file_hash = compute_file_hash(file_path)
    print(f"Computed hash: {file_hash}")
    
    if file_hash != known_good_hash:
        print("Warning: The file has been modified! Possible patch injection detected.")
    else:
        print("The file is intact. No patch injection detected.")

def main():
    
    
    # Get file path from the user
    file_path = input("Please enter the path of the executable file to analyze:").strip()
    
    if not os.path.isfile(file_path):
        print(f"Error: The file '{file_path}' does not exist or is not a valid file.")
        return

    # Optionally, you could store the known good hash somewhere (e.g., a configuration file)
    # For demonstration, we will use a placeholder known hash
    known_good_hash = "put_the_known_good_sha256_hash_here"
    
    # Check for patch injection by comparing the file hash to the known good hash
    check_for_patch(file_path, known_good_hash)
    
    # If it's a Windows executable, perform PE file analysis
    if file_path.lower().endswith('.exe'):
        analyze_pe_file(file_path)
    else:
        print("The file is not a Windows executable (.exe). No PE analysis performed.")
    
    print("Analysis complete.")

if __name__ == "__main__":
    main()

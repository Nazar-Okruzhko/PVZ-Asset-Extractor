#!/usr/bin/env python3
"""
Plants vs Zombies PAK File Extractor
Port of the QuickBMS script to Python with enhancements
"""

import os
import sys
import struct
from pathlib import Path

class PvzPakExtractor:
    def __init__(self):
        self.passwords = [
            "1celowniczy23osral4kibel",
            "www#quarterdigi@com", 
            "bigfish",
            ""
        ]
        self.use_compression = False  # Set to True for Zuma's Revenge! PS3
    
    def xor_data(self, data, key):
        """Apply XOR decryption to data with given key"""
        if not key:
            return data
        
        result = bytearray()
        key_len = len(key)
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        return bytes(result)
    
    def find_correct_key(self, file_data):
        """Try different passwords and XOR keys to find the correct decryption"""
        # Try passwords first
        for password in self.passwords:
            if password:
                key = [ord(c) for c in password]
            else:
                key = []
            
            # Try with password-based XOR
            test_data = self.xor_data(file_data[:4], key)
            if len(test_data) >= 4:
                signature = struct.unpack('<I', test_data)[0]
                if signature == 0xbac04ac0:
                    return key
        
        # Try classical 0xf7 XOR
        test_data = self.xor_data(file_data[:4], [0xf7])
        signature = struct.unpack('<I', test_data)[0]
        if signature == 0xbac04ac0:
            return [0xf7]
        
        # Scan through single byte XOR keys
        for xor_key in range(0xff, 0, -1):
            test_data = self.xor_data(file_data[:4], [xor_key])
            signature = struct.unpack('<I', test_data)[0]
            if signature == 0xbac04ac0:
                return [xor_key]
        
        return None
    
    def extract_pak(self, pak_file_path, output_dir=None):
        """Extract contents of a PAK file"""
        if output_dir is None:
            output_dir = Path(pak_file_path).parent / "main"
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"Reading PAK file: {pak_file_path}")
        with open(pak_file_path, 'rb') as f:
            file_data = f.read()
        
        print("Finding correct decryption key...")
        xor_key = self.find_correct_key(file_data)
        
        if xor_key is None:
            print("Error: Not a valid 7½7M archive or password not found")
            return False
        
        print(f"Using XOR key: {xor_key}")
        
        # Decrypt the entire file
        decrypted_data = self.xor_data(file_data, xor_key)
        
        # Parse the header
        pos = 0
        signature = struct.unpack_from('<I', decrypted_data, pos)[0]
        pos += 4
        
        if signature != 0xbac04ac0:
            print("Error: Invalid signature after decryption")
            return False
        
        version = struct.unpack_from('<I', decrypted_data, pos)[0]
        pos += 4
        
        print(f"Archive version: {version}")
        
        # First pass: collect file entries and calculate data offset
        file_entries = []
        current_pos = pos
        
        while True:
            if current_pos >= len(decrypted_data):
                break
                
            flags = decrypted_data[current_pos]
            current_pos += 1
            
            if flags & 0x80:  # FILEFLAGS_END
                break
                
            name_size = decrypted_data[current_pos]
            current_pos += 1
            
            filename = decrypted_data[current_pos:current_pos + name_size].decode('latin-1')
            current_pos += name_size
            
            size = struct.unpack_from('<I', decrypted_data, current_pos)[0]
            current_pos += 4
            
            if self.use_compression:
                compressed_size = struct.unpack_from('<I', decrypted_data, current_pos)[0]
                current_pos += 4
            else:
                compressed_size = 0
            
            timestamp = struct.unpack_from('<Q', decrypted_data, current_pos)[0]
            current_pos += 8
            
            file_entries.append({
                'filename': filename,
                'size': size,
                'compressed_size': compressed_size,
                'offset': 0,  # Will be set in second pass
                'timestamp': timestamp
            })
        
        # Calculate data offset (after all file entries)
        data_offset = current_pos
        
        # Second pass: extract files
        print(f"Found {len(file_entries)} files")
        print(f"Data starts at offset: 0x{data_offset:X}")
        
        current_data_pos = data_offset
        extracted_count = 0
        
        for entry in file_entries:
            entry['offset'] = current_data_pos
            
            output_path = output_dir / entry['filename']
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            print(f"Extracting: {entry['filename']} ({entry['size']} bytes)")
            
            file_data = decrypted_data[current_data_pos:current_data_pos + entry['size']]
            
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            current_data_pos += entry['size']
            extracted_count += 1
        
        print(f"Successfully extracted {extracted_count} files to: {output_dir}")
        return True

def main():
    if len(sys.argv) < 2:
        if len(sys.argv) == 1 and hasattr(sys, 'frozen'):
            # If running as executable, wait for drag and drop
            input("Drag and drop a main.pak file onto this executable, then press Enter...")
            return
        else:
            print("Usage: pvz_extractor.py <path_to_main.pak> [output_directory]")
            print("Or drag and drop a main.pak file onto this script")
            return
    
    pak_file = sys.argv[1]
    
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    else:
        output_dir = None
    
    if not os.path.exists(pak_file):
        print(f"Error: File not found: {pak_file}")
        return
    
    extractor = PvzPakExtractor()
    success = extractor.extract_pak(pak_file, output_dir)
    
    if success:
        print("Extraction completed successfully!")
    else:
        print("Extraction failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()

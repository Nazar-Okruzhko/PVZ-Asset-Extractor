#!/usr/bin/env python3
"""
Plants vs Zombies PAK File Extractor and Repacker
Port of the QuickBMS script to Python with enhancements
"""

import os
import sys
import struct
import json
from pathlib import Path
from datetime import datetime

class PvzPakExtractor:
    def __init__(self):
        self.passwords = [
            "1celowniczy23osral4kibel",
            "www#quarterdigi@com", 
            "bigfish",
            ""
        ]
        self.use_compression = False
    
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
        for password in self.passwords:
            if password:
                key = [ord(c) for c in password]
            else:
                key = []
            
            test_data = self.xor_data(file_data[:4], key)
            if len(test_data) >= 4:
                signature = struct.unpack('<I', test_data)[0]
                if signature == 0xbac04ac0:
                    return key
        
        test_data = self.xor_data(file_data[:4], [0xf7])
        signature = struct.unpack('<I', test_data)[0]
        if signature == 0xbac04ac0:
            return [0xf7]
        
        for xor_key in range(0xff, 0, -1):
            test_data = self.xor_data(file_data[:4], [xor_key])
            signature = struct.unpack('<I', test_data)[0]
            if signature == 0xbac04ac0:
                return [xor_key]
        
        return None
    
    def extract_pak(self, pak_file_path, output_dir=None):
        """Extract contents of a PAK file and create manifest for repacking"""
        pak_file_path = Path(pak_file_path)
        
        if not pak_file_path.exists():
            if not pak_file_path.suffix:
                pak_file_path = pak_file_path.with_suffix('.pak')
                if not pak_file_path.exists():
                    print(f"Error: File not found: {pak_file_path}")
                    return False
            else:
                print(f"Error: File not found: {pak_file_path}")
                return False
        
        if pak_file_path.is_dir():
            print(f"Error: {pak_file_path} is a directory, not a PAK file")
            print("For repacking, drag and drop the folder directly onto the script")
            return False
        
        if output_dir is None:
            output_dir = pak_file_path.parent / "main"
        
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
        
        decrypted_data = self.xor_data(file_data, xor_key)
        
        pos = 0
        signature = struct.unpack_from('<I', decrypted_data, pos)[0]
        pos += 4
        
        if signature != 0xbac04ac0:
            print("Error: Invalid signature after decryption")
            return False
        
        version = struct.unpack_from('<I', decrypted_data, pos)[0]
        pos += 4
        
        print(f"Archive version: {version}")
        
        file_entries = []
        current_pos = pos
        
        while True:
            if current_pos >= len(decrypted_data):
                break
                
            flags = decrypted_data[current_pos]
            current_pos += 1
            
            if flags & 0x80:
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
                'timestamp': timestamp,
                'flags': flags
            })
        
        data_offset = current_pos
        
        print(f"Found {len(file_entries)} files")
        print(f"Data starts at offset: 0x{data_offset:X}")
        
        current_data_pos = data_offset
        unpacked_count = 0
        
        for entry in file_entries:
            entry['offset'] = current_data_pos
            
            output_path = output_dir / entry['filename']
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            print(f"Unpacking: {entry['filename']} ({entry['size']} bytes)")
            
            file_data = decrypted_data[current_data_pos:current_data_pos + entry['size']]
            
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            current_data_pos += entry['size']
            unpacked_count += 1
        
        # Create compact manifest - only store what's absolutely necessary
        manifest = {
            'version': 1,
            'xor_key': xor_key,
            'files': []
        }
        
        # Store files in compact format: [filename, size, timestamp, flags]
        # Only include flags if non-zero to save space
        for entry in file_entries:
            file_info = [entry['filename'], entry['size'], entry['timestamp']]
            if entry['flags'] != 0:
                file_info.append(entry['flags'])
            manifest['files'].append(file_info)
        
        # Save as compact JSON
        manifest_file = output_dir / "manifest"
        with open(manifest_file, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, separators=(',', ':'), ensure_ascii=False)
        
        print(f"Successfully unpacked {unpacked_count} files to: {output_dir}")
        print(f"Manifest saved to: {manifest_file}")
        return True

    def repack_pak(self, input_dir, output_pak_path=None):
        """Repack files from directory back into PAK format using manifest"""
        input_dir = Path(input_dir)
        
        if not input_dir.exists():
            print(f"Error: Directory not found: {input_dir}")
            return False
        
        # Find manifest file
        manifest_file = input_dir / "manifest"
        
        if not manifest_file.exists():
            print(f"Error: Manifest file not found: {manifest_file}")
            print("Please make sure you're pointing to a folder that was extracted by this tool")
            return False
        
        print(f"Reading manifest from: {manifest_file}")
        with open(manifest_file, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        
        # Determine output PAK file path
        if output_pak_path is None:
            output_pak_path = input_dir.parent / "main.pak"
        
        output_pak_path = Path(output_pak_path)
        
        print(f"Repacking files from: {input_dir}")
        print(f"Output PAK file: {output_pak_path}")
        
        # Build header
        header_data = bytearray()
        
        # Add signature and version (always 0 for PvZ)
        header_data.extend(struct.pack('<I', 0xbac04ac0))
        header_data.extend(struct.pack('<I', 0))
        
        # Add file entries
        file_entries = manifest['files']
        
        for i, file_info in enumerate(file_entries):
            # Parse compact file info
            filename = file_info[0]
            size = file_info[1] 
            timestamp = file_info[2]
            flags = file_info[3] if len(file_info) > 3 else 0
            
            # Set end flag on last file
            if i == len(file_entries) - 1:
                flags |= 0x80
            
            header_data.append(flags)
            header_data.append(len(filename))
            header_data.extend(filename.encode('latin-1'))
            header_data.extend(struct.pack('<I', size))
            header_data.extend(struct.pack('<Q', timestamp))
        
        # Collect file data
        file_data = bytearray()
        
        print(f"Processing {len(file_entries)} files...")
        
        for file_info in file_entries:
            filename = file_info[0]
            file_path = input_dir / filename
            
            if not file_path.exists():
                print(f"Error: File not found: {file_path}")
                return False
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            file_data.extend(data)
            print(f"Repacked: {filename} ({len(data)} bytes)")
        
        # Combine header and file data
        pak_data = header_data + file_data
        
        # Apply XOR encryption
        xor_key = manifest['xor_key']
        encrypted_data = self.xor_data(pak_data, xor_key)
        
        # Write output PAK file
        with open(output_pak_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"\nSuccessfully repacked {len(file_entries)} files to: {output_pak_path}")
        print(f"Final PAK file size: {len(encrypted_data)} bytes")
        
        return True

def main():
    if len(sys.argv) < 2:
        if len(sys.argv) == 1 and hasattr(sys, 'frozen'):
            # Drag and drop support
            input_path = input("Drag and drop a main.pak file or extracted 'main' folder onto this executable, then press Enter...").strip().strip('"')
            
            if not input_path:
                return
                
            input_path = Path(input_path)
            
            if input_path.is_file() and (input_path.suffix == '.pak' or input_path.name == 'main.pak'):
                # It's a PAK file - unpack it
                extractor = PvzPakExtractor()
                success = extractor.extract_pak(input_path)
                if success:
                    print("Unpacking completed successfully!")
                else:
                    print("Unpacking failed!")
                    sys.exit(1)
                    
            elif input_path.is_dir():
                # It's a folder - check if it has manifest and repack it
                if (input_path / "manifest").exists():
                    extractor = PvzPakExtractor()
                    success = extractor.repack_pak(input_path)
                    if success:
                        print("Repacking completed successfully!")
                    else:
                        print("Repacking failed!")
                        sys.exit(1)
                else:
                    print(f"Error: {input_path} doesn't appear to be an extracted PAK folder (missing manifest)")
                    print("Please drag and drop a valid main.pak file or extracted folder")
            else:
                print("Error: Please drag and drop either a main.pak file or an extracted 'main' folder")
            return
        else:
            print("Plants vs Zombies PAK Extractor and Repacker")
            print("Usage:")
            print("  Unpacking: pvz_extractor.py <path_to_main.pak> [output_directory]")
            print("  Repacking:  pvz_extractor.py --repack <extracted_folder> [output_pak_file]")
            print("\nOr simply drag and drop:")
            print("  - A main.pak file to unpack it") 
            print("  - An extracted 'main' folder to repack it")
            print("\nExamples:")
            print('  pvz_extractor.py "main.pak"')
            print('  pvz_extractor.py --repack "main"')
            return
    
    # Check if we're in repack mode
    if sys.argv[1] == '--repack' or sys.argv[1] == '-r':
        if len(sys.argv) < 3:
            print("Error: Please specify extracted folder for repacking")
            print("Usage: pvz_extractor.py --repack <extracted_folder> [output_pak_file]")
            return
        
        input_dir = sys.argv[2]
        output_pak = sys.argv[3] if len(sys.argv) > 3 else None
        
        extractor = PvzPakExtractor()
        success = extractor.repack_pak(input_dir, output_pak)
        
        if success:
            print("Repacking completed successfully!")
        else:
            print("Repacking failed!")
            sys.exit(1)
    else:
        # Unpacking mode
        pak_file = sys.argv[1]
        
        if len(sys.argv) > 2:
            output_dir = sys.argv[2]
        else:
            output_dir = None
        
        extractor = PvzPakExtractor()
        success = extractor.extract_pak(pak_file, output_dir)
        
        if success:
            print("Unpacking completed successfully!")
            if output_dir:
                extracted_folder = output_dir
            else:
                pak_path = Path(pak_file)
                extracted_folder = pak_path.parent / "main"
            print(f"\nTo repack later, either:")
            print(f'  pvz_extractor.py --repack "{extracted_folder}"')
            print(f"  Or drag and drop the '{extracted_folder}' folder onto this script")
        else:
            print("Unpacking failed!")
            sys.exit(1)

if __name__ == "__main__":
    main()

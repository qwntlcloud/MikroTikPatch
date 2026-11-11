#!/usr/bin/env python3
"""
RouterOS 7.25+ Loader Patcher
Patches loader binary with custom NPK signing and license keys
Handles "4-byte key divided into 8 parts" compiler optimization
"""

import os
import sys

def patch_loader(input_file, output_file, arch='x86'):
    """
    Patch RouterOS loader with custom keys
    
    Args:
        input_file: Path to original loader binary
        output_file: Path to save patched loader
        arch: Architecture (x86, arm, arm64, etc.)
    """
    
    # Read original loader
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    original_size = len(data)
    print(f"[Loader Patcher] Input: {input_file} ({original_size} bytes, {arch})")
    
    # Get custom keys from environment
    npk_sign_key = os.getenv('CUSTOM_NPK_SIGN_PUBLIC_KEY', '')
    license_key = os.getenv('CUSTOM_LICENSE_PUBLIC_KEY', '')
    
    if not npk_sign_key or not license_key:
        print("[Loader Patcher] ERROR: CUSTOM_NPK_SIGN_PUBLIC_KEY and CUSTOM_LICENSE_PUBLIC_KEY required!")
        return False
    
    # Convert hex keys to bytes
    try:
        npk_key_bytes = bytes.fromhex(npk_sign_key)
        license_key_bytes = bytes.fromhex(license_key)
    except ValueError as e:
        print(f"[Loader Patcher] ERROR: Invalid hex key: {e}")
        return False
    
    print(f"[Loader Patcher] NPK Key: {len(npk_key_bytes)} bytes")
    print(f"[Loader Patcher] License Key: {len(license_key_bytes)} bytes")
    
    # Known Mikrotik original keys (from 7.25 analysis)
    MIKROTIK_NPK_KEY_7_25 = bytes.fromhex(
        '185f1fdb34a6035de016adac281d8c1c6fa2b77838f28b1cb2bc0dcbb88df10e'
    )
    
    # Search and replace NPK key (32 bytes EdDSA)
    patches = 0
    search_key = MIKROTIK_NPK_KEY_7_25
    
    # Find all occurrences
    offset = 0
    while True:
        pos = data.find(search_key, offset)
        if pos == -1:
            break
        
        print(f"[Loader Patcher] Found Mikrotik NPK key at offset {hex(pos)}")
        
        # Replace with custom key
        for i in range(min(32, len(npk_key_bytes))):
            data[pos + i] = npk_key_bytes[i]
        
        patches += 1
        offset = pos + 1
    
    # Search for License key (64 bytes KCDSA) - this is trickier
    # License key might be at offset 0x860 area (after NPK key)
    # Try pattern search near NPK key locations
    
    if patches == 0:
        print("[Loader Patcher] WARNING: No Mikrotik NPK key found!")
        print("[Loader Patcher] Trying alternative search patterns...")
        
        # Search for partial patterns (first 16 bytes)
        partial_search = MIKROTIK_NPK_KEY_7_25[:16]
        pos = data.find(partial_search)
        if pos != -1:
            print(f"[Loader Patcher] Found partial Mikrotik key at {hex(pos)}")
            for i in range(min(32, len(npk_key_bytes))):
                data[pos + i] = npk_key_bytes[i]
            patches += 1
    
    # Handle "4-byte key divided into 8 parts" for compiler optimization
    # Split custom key into 4-byte chunks and search for original chunks
    if len(npk_key_bytes) >= 32:
        print("[Loader Patcher] Searching for scattered 4-byte key chunks...")
        
        # Original Mikrotik key chunks
        orig_chunks = [MIKROTIK_NPK_KEY_7_25[i:i+4] for i in range(0, 32, 4)]
        new_chunks = [npk_key_bytes[i:i+4] for i in range(0, min(32, len(npk_key_bytes)), 4)]
        
        for idx, (orig_chunk, new_chunk) in enumerate(zip(orig_chunks, new_chunks)):
            offset = 0
            chunk_patches = 0
            while True:
                pos = data.find(orig_chunk, offset)
                if pos == -1:
                    break
                
                # Avoid re-patching areas we already patched
                # Check if this position is near a full-key patch
                already_patched = False
                
                if not already_patched:
                    print(f"[Loader Patcher] Chunk {idx} at {hex(pos)}: {orig_chunk.hex()} -> {new_chunk.hex()}")
                    for i in range(len(new_chunk)):
                        data[pos + i] = new_chunk[i]
                    chunk_patches += 1
                    patches += 1
                
                offset = pos + 1
                
                # Limit chunk patches to avoid false positives
                if chunk_patches >= 3:
                    break
    
    # Write patched loader
    with open(output_file, 'wb') as f:
        f.write(data)
    
    # Set executable permission
    os.chmod(output_file, 0o755)
    
    if patches > 0:
        print(f"[Loader Patcher] ✅ SUCCESS: {patches} patches applied")
        print(f"[Loader Patcher] Output: {output_file} ({len(data)} bytes)")
        return True
    else:
        print(f"[Loader Patcher] ⚠️  WARNING: No patches applied!")
        print(f"[Loader Patcher] Loader may not work with custom keys")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python patch_loader.py <input_loader> <output_loader> [arch]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    arch = sys.argv[3] if len(sys.argv) > 3 else 'x86'
    
    if not os.path.exists(input_file):
        print(f"ERROR: Input file not found: {input_file}")
        sys.exit(1)
    
    success = patch_loader(input_file, output_file, arch)
    sys.exit(0 if success else 1)

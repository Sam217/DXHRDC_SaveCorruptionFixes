import os
import struct
import binascii

def update_saveindex(saves_dir, save_name, save_path):
    index_path = os.path.join(saves_dir, "saveindex")
    if not os.path.exists(index_path):
        return False
        
    with open(index_path, 'rb') as f:
        data = bytearray(f.read())
        
    name_bytes = save_name.encode('ascii') + b'\0'
    
    # Ensure we find the exact name block. Name is exactly 32 bytes long, null padded.
    # We can just search for name_bytes.
    pos = data.find(name_bytes)
    if pos == -1:
        return False
        
    # Verify it's preceded by the record boundary or fits the 32 byte block?
    # Usually it's just searching for the name is safe enough if we match \0
    
    new_size = os.path.getsize(save_path)
    with open(save_path, 'rb') as f:
        file_data = f.read()
    new_crc = binascii.crc32(file_data) & 0xFFFFFFFF
    
    size_offset = pos + 32
    crc_offset = pos + 32 + 4 + 8 + 4
    
    data[size_offset:size_offset+4] = struct.pack('<I', new_size)
    data[crc_offset:crc_offset+4] = struct.pack('<I', new_crc)
    
    with open(index_path, 'wb') as f:
        f.write(data)
    return True

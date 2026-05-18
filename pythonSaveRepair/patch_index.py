import os
import struct
import binascii


def patch_saveindex(index_path, save_name, new_file_path):
    with open(index_path, 'rb') as f:
        data = bytearray(f.read())

    num_entries = struct.unpack('<I', data[:4])[0]
    entry_size = 53  # observed pattern length? Let's find the save_name.

    name_bytes = save_name.encode('ascii') + b'\0'
    pos = data.find(name_bytes)

    if pos == -1:
        print(f"Save {save_name} not found in index.")
        return

    print(f"Found {save_name} at offset {hex(pos)}")

    new_size = os.path.getsize(new_file_path)
    with open(new_file_path, 'rb') as f:
        file_data = f.read()
    new_crc = binascii.crc32(file_data) & 0xFFFFFFFF

    # Structure from start of name:
    # 32 bytes for name (null padded)
    # 4 bytes for file size
    # 8 bytes for FILETIME
    # 4 bytes for unknown/flag
    # 4 bytes for CRC32

    size_offset = pos + 32
    crc_offset = pos + 32 + 4 + 8 + 4

    old_size = struct.unpack('<I', data[size_offset:size_offset+4])[0]
    old_crc = struct.unpack('<I', data[crc_offset:crc_offset+4])[0]

    print(f"Old Size: {old_size}, Old CRC: {hex(old_crc)}")
    print(f"New Size: {new_size}, New CRC: {hex(new_crc)}")

    data[size_offset:size_offset+4] = struct.pack('<I', new_size)
    data[crc_offset:crc_offset+4] = struct.pack('<I', new_crc)

    # Overwrite the original save file with the repacked one
    import shutil
    target_save_path = os.path.join(os.path.dirname(index_path), save_name)
    if target_save_path != new_file_path:
        shutil.copy2(new_file_path, target_save_path)
        print(f"Overwrote {target_save_path} with new save.")

    # Write back the patched index
    with open(index_path, 'wb') as f:
        f.write(data)
    print("Patched saveindex successfully.")


patch_saveindex(
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\saveindex',
    'GAMER3_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER3_4'
)

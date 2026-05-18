import sys
import os
sys.path.insert(0, 'pythonSaveRepair')
from save_repair_tool import read_save

# PC Inventory items: (4-byte hex ID little-endian string, friendly name)
PC_INVENTORY_ITEMS = [
    ("6a260000", "Painkillers"),
    ("d0250000", "Nuke_Virus_Software"), # Guessed based on proximity to old ID
    ("6e260000", "Stop_Worm_Software"),
    ("a54b0000", "PEPS_Energy_Pack"),
    ("a44a0000", "Typhoon_Ammo"),
    ("ce200000", "Tranquilizer_Darts"),
    ("3a240000", "Combat_Rifle_Ammo"),
    ("8a1f0000", "Shotgun_Cartridges"),
    ("6a030000", "10mm_Pistol_Ammo"),
    ("64830000", "Laser_Rifle_Battery"),
    ("63830000", "Plasma_Capsules"),
    ("22dd0000", "Golden_Phoenix_Sling"),
    ("72450000", "Machine_Pistol_Ammo"),
    ("21dd0000", "Shanghai_Gu_Punch"),
    ("fab60000", "Auto_Hacker"),
]

saves = [
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER51_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER5_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER25_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER63_4'
]

for save_path in saves:
    name = os.path.basename(save_path)
    print(f"\n=== {name} ===")
    try:
        buf = read_save(save_path)
        for id_hex, item_name in PC_INVENTORY_ITEMS:
            id_bytes = bytes.fromhex(id_hex)
            hits = [i for i in range(len(buf)-4) if buf[i:i+4] == id_bytes]
            if not hits:
                continue
            for h in hits:
                flag = int.from_bytes(buf[h+4:h+6], 'little')
                count = int.from_bytes(buf[h+6:h+8], 'little')
                x = int.from_bytes(buf[h+8:h+12], 'little')
                y = int.from_bytes(buf[h+12:h+16], 'little')
                rot = int.from_bytes(buf[h+16:h+20], 'little', signed=True)
                
                # Filter out obvious false positives (insane grid coordinates)
                if x > 100 or y > 100:
                    continue
                    
                print(f"  {item_name}: Count={count}, Pos=({x}, {y}), Rot={rot}")
    except Exception as e:
        print(f"  Error reading: {e}")

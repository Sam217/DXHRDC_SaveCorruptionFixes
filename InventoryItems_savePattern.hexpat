// Enter your pattern code here and click on the Play button
// below to execute your code. The results will then be visible
// in the Pattern Data view.
// 
// More information can be found in the documentation.
// 
// 
// Simple example:
// 
// import std.io;
// 
// struct Pattern {
//     u32 int;
//     float floating_point;
// };
// 
import std.io;

#pragma endian little
    
struct InventoryItem {
     u32 itemID;   // 4 bytes: 6A 26 00 00 -> 9834
     u16 flag;     // 2 bytes: 01 00 -> 1
     u16 count;    // 2 bytes: 04 00 -> 4
     u32 posX;     // 4 bytes: 0B 00 00 00 -> 11
     u32 posY;     // 4 bytes: 06 00 00 00 -> 6
     s32 rotation; // 4 bytes: 27 FF FF FF -> -217
     //u8 extra[20]; // 20 bytes: Engine metadata/padding
};
 
InventoryItem Ox6A26_painKillers @ 0x1A9811;
std::print("Item ID: 0x{:08X}", Ox6A26_painKillers.itemID);
std::print("Inventory position: {}, {}", Ox6A26_painKillers.posX, Ox6A26_painKillers.posY);
std::print("Flag: 0x{:08X}, COUNT: {}", Ox6A26_painKillers.flag, Ox6A26_painKillers.count);

InventoryItem OxE52C_cyberBoostProEnergy0 @ 0x1A9681;
InventoryItem OxE52C_cyberBoostProEnergy1 @ 0x1A96D1;
InventoryItem Ox5826_CyberBoostProEnergyPack @ 0x1A9401;
InventoryItem Ox1B4D_CyberBoostProEnergyJar @ 0x1A93B1;
InventoryItem Ox0B2C01_Vodka @ 0x1A9339;

InventoryItem OxA3C2_autoUnlockDevice @ 0x1A9771;
InventoryItem OxB92C_NukeVirus @ 0x1A95E1;
InventoryItem OxF42D_StopWorm @ 0x1A9569;

InventoryItem Ox4929_FR27autoRifle_silencer @ 0x1A9749;
InventoryItem Ox14FF_GrenadeLauncher @ 0x1A9659;
InventoryItem OxF11E_Pistol_fullUpgrade @ 0x1A94A1;
InventoryItem Ox019A_tranquilizerRifle_withUpgrades @ 0x1A96A9;

InventoryItem Ox7221_rifleAmmo0 @ 0x1A92C1;
InventoryItem Ox7221_rifleAmmo2 @ 0x1A9299;
InventoryItem Ox7221_rifleAmmo1 @ 0x1A9631;
InventoryItem Ox335F_TyphoonAmmo0 @ 0x1A94F1;
InventoryItem Ox335F_TyphoonAmmo1 @ 0x1A9479;
InventoryItem Ox335F_TyphoonAmmo2 @ 0x1A95B9;
InventoryItem Ox6C2E_tranqDarts0 @ 0x1A92E9;
InventoryItem Ox6C2E_tranqDarts1 @ 0x1A9609;
InventoryItem Ox08FF_GrenadeLauncher_Ammo @ 0x1A97C1;
InventoryItem OxFC05_PistolAmmo0 @ 0x1A9311;
InventoryItem OxFC05_PistolAmmo1 @ 0x1A9361;

InventoryItem Ox3D29_AmmoUpgrade @ 0x1A94C9;
InventoryItem Ox6860_LaserTargetingUpgrade @ 0x1A9429;

InventoryItem OxCB1C_stickyMine0 @ 0x1A9799;
InventoryItem OxCB1C_stickyMine1 @ 0x1A9839;

InventoryItem OxFD05_Grenade0 @ 0x1A9519;
InventoryItem OxFD05_Grenade1 @ 0x1A9541;
InventoryItem OxFE05_FlashBang1 @ 0x1A9591;
InventoryItem OxE059_EMPgrenade0 @ 0x1A9271;
InventoryItem OxE059_EMPgrenade1 @ 0x1A9451;
InventoryItem OxE059_EMPgrenade2 @ 0x1A9721;
InventoryItem OxE059_EMPgrenade3 @ 0x1A97E9;
InventoryItem OxDF59_EMPmine0 @ 0x1A96F9;
InventoryItem OxA372_RemoteDetonateBomb0 @ 0x1A93D9;
InventoryItem OxA372_RemoteDetonateBomb1_buggedPosAsGrenadeAmmo @ 0x1A9389;
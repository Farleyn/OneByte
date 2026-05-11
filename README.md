# Onebyte

Lightweight external cheat for legacy CS:GO that toggles wallhack and radar via single-byte memory modifications. Built for educational and reverse engineering purposes.

## Features
- Toggle wallhack & radar in-game
- Single-byte modification per feature
- External execution (no DLL injection)
- Instant state restoration
- Minimalistic console interface

## Controls
| Key | Action          |
|-----|-----------------|
| `1` | Toggle Wallhack |
| `2` | Toggle Radar    |
| `0` | Exit / Restore  |

## Requirements
- Windows
- Visual Studio (C++17, x86 Release)
- Legacy Steam CS:GO client

## Build & Usage
1. Compile as `x86 Release`.
2. Launch `csgo.exe`, then run `onebyte.exe`.
3. Use the hotkeys above. Launch order does not matter.

## Technical Overview
Directly modifies conditional check opcodes in game memory. Single-byte changes ensure fast execution, minimal overhead, and trivial restoration.

## Disclaimer
Strictly for educational and reverse engineering research. Do not use in environments violating terms of service. Use at your own risk.

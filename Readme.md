# FileHider

Kernel minifilter + WinForms UI. Hides selected files completely
from user-mode enumeration and file opens. Admin can't see them
either — the filtering happens below the filesystem, not via the
hidden attribute.

## Requirements

- Visual Studio 2022 with **Desktop development with C++** workload
- **Windows Driver Kit (WDK) 10** matching your Windows SDK
  (VS Installer → Individual components → search "WDK")
- **RTCore64.bin** in the project root — the MSI Afterburner driver,
  renamed from `.sys` to `.bin` so VS doesn't try to sign it
- HVCI / Memory Integrity **OFF** — Core Isolation in Windows Security

## How to build

### From Visual Studio

1. Double-click `FileHider.sln`.
2. Select **Release | x64**.
3. Build → Build Solution (`Ctrl+Shift+B`).

VS calls `build.bat` via the vcxproj's NMake target.

### From cmd

```bat
build.bat Release
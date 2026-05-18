# Handle hijacking

actual handle hijacking without duplicating the handle, just enumerates the handles already open by the parent process and takes the one that has `PROCESS_ALL_ACCESS` to the target

target process is hardcoded in `dllmain.cpp`:
```cpp
HANDLE handle = GetHandle(L"cs2.exe");
```

## requirements

- Windows 11 25H2 (handle type index is hardcoded to 8, may differ on older versions)
- [phnt](https://github.com/winsiderss/phnt) - i used vcpkg
- MSVC

## credits

based on [paskalian/HandleHijacking](https://github.com/paskalian/HandleHijacking)

![preview](preview.png)

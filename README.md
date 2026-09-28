# Manual PE Mapper

A small Windows DLL manual mapper written in C++.

I originally wrote this project toward the end of 2022 while experimenting with game hacking and internal cheats, mainly as a way to better understand PE files, DLL loading, process memory, and the Windows loader.

Instead of loading the target DLL directly through the Windows API `LoadLibrary`, the mapper copies the image into the target process and performs the basic loading steps manually.

## Features

- Maps PE sections into a target process
- Copies and executes a small loader routine in the target process
- Applies base relocations
- Resolves imported functions
- Loads dependency DLLs through `LoadLibraryA`
- Resolves imports through `GetProcAddress`
- Calls the DLL entry point (`DllMain`)

## Limitations

This is an older experimental project and not a complete implementation of the Windows PE loader.

- Primarily written and tested for x86
- x64 support would require some refactoring of pointer sizes, relocations and import handling
- TLS callbacks / static TLS are not handled
- Imports by ordinal are currently not handled
- Dependency DLLs are still loaded using the normal Windows loader
- Does not reproduce all behavior of the Windows loader

The project was written for learning and experimentation and should be treated as such.

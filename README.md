# PatternFinder

## Examples of different usages

```cpp
FindPattern(
  GetModuleHandleW(nullptr),
  reinterpret_cast<const unsigned char*>("\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\x5C\x24\x00\x48\x8B\xC7"), // opcode bytes
  "xxx????xxxx?xxx" // mask
  );
```

```cpp
FindPattern(
  GetModuleHandleW(nullptr), 
  "48 8B 3D ? ? ? ? 48 8B 5C 24 ? 48 8B C7" // opcode bytes
  );
```

```cpp
FindPattern<const unsigned char*>(
  GetModuleHandleW(nullptr), 
  "48 8D 05 ? ? ? ? 33 F6 48 89 01 48 89 71 10 45 8B D9 41 B9 FF FF FF FF", // opcode bytes
  0, // address offset
  3, // instruction offset
  7 // instruction size
  );
```

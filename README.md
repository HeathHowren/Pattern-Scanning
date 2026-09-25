# Pattern-Scanning

An external array-of-byte (AOB) pattern scanner in C++, written for the [Pattern scanning lesson](https://www.youtube.com/watch?v=sS7Xgtqc1yc) on the [Cyborg Elf YouTube channel](https://www.youtube.com/@CyborgElf).

> **Legacy code, kept for education.** Written in 2020 against CS:GO, which has since been replaced by CS2, so the signature and window name here no longer match anything. The technique is unchanged: it is how tools find code that moves between builds. Practice on software you own or on open-source games, never on online multiplayer games.

## What a pattern scan is

Hard-coded addresses and offsets break every time a game is rebuilt. The instructions that *use* those offsets usually do not change, though, so you can search for their bytes instead:

```
8B 0D ?? ?? ?? ?? 8B 01 FF 50
```

Each `??` is a wildcard for the bytes that do change, typically the address being loaded. When the pattern matches, the scanner reads the value at a fixed offset from the match and has the fresh address, whatever build is running.

## How this example works

1. Finds the window and opens the process.
2. Looks up the target module with `CreateToolhelp32Snapshot`, `Module32First` and `Module32Next`.
3. Copies the whole module into a local buffer with one `ReadProcessMemory` call.
4. Walks the buffer against an IDA-style pattern string with `??` wildcards (`find_pattern`).
5. Reads the 4-byte address embedded in the matched instruction, adds the extra offset, and uses it with typed `RPM<T>` and `WPM<T>` helpers.

Everything is in [`patternscanexternal/Source.cpp`](patternscanexternal/Source.cpp).

## Building

Open `patternscanexternal.sln` in Visual Studio, set the character set to **Multi-Byte**, and build as **x86**.

## Related

- [CSGO-Cheats](https://github.com/HeathHowren/CSGO-Cheats): the series this scanner was written to fix, where every offset was hard-coded.
- [Pointer Lab](https://gamereversal.club/tools/pointer-lab/): a free, open-source memory tool with byte-pattern search built in.
- Pattern scanning is covered in full in chapter 14 of [The Game Hacker's Handbook](https://gamereversal.club/books/game-hackers-handbook/).
- More companion code: [gamereversal.club/course-materials](https://gamereversal.club/course-materials/).

## Author

Heath Howren, known online as Cyborg Elf. Questions go to the [Game Reversal Club Discord](https://discord.gg/NwRFmp3J2J). MIT licensed, see [LICENSE](LICENSE).

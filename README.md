# ps5-self-pager

It works by swapping `pagertab[OBJT_VNODE]` to point to `selfpagerops` instead of the `vnodepagerops` it normally is for the duration of the `mmap` call, this will cause the kernel to give us a self pager when mmapping a file, essentially replicating the removed `MAP_SELF` `mmap` flag, while bypassing its checks.

Supports PS5 firmware `1.00`-`13.40`

## Usage
There are a couple different builds in the releases to dump specific folders:
| Payload file name | File(s)/folder(s) it dumps |
| -------- | ------- |
| ps5-self-pager-game.elf | `/mnt/sandbox/pfsmnt` recursively (`app0` and `patch0` if exists, `app0-patch0-union` is skipped), plus mounted ShadowMount-style titles under `/system_ex/app` |
| ps5-self-pager-full-system.elf | `/system` and `/system_ex` recursively |
| ps5-self-pager-system-common-lib.elf | `/system/common/lib` |
| ps5-self-pager-shellcore.elf | `/system/vsh/SceShellCore.elf` |

If a USB drive is plugged in, it will output the decrypted unsigned ELFs to `USB0/dump`, otherwise it will use `/data/dump` on the internal storage.

Send to [elfldr](https://github.com/ps5-payload-dev/elfldr) (port 9021) with a sender that can listen back to see logs:
- For a GUI option: https://github.com/Al-Azif/hermes-link
    - Select `Debug Log` in the menu to see logs
- If you have `PuTTY` installed, from `cmd` do:
    ```
    type ps5-self-pager.elf | "c:\Program Files\PuTTY\plink.exe" -raw -P 9021 IP_OF_YOUR_PS5
    ```
- Using socat:
    ```
    socat -t 9999999 - TCP:IP_OF_YOUR_PS5:9021 < ps5-self-pager.elf
    ```

Wait until you see `Done. Success: x, Failed: y` in the logs.

## Mounted games and plaintext SELF containers

Directory entries reported as `DT_UNKNOWN` are classified with `lstat` before
traversal or file filtering. Symlinks remain excluded. The extensions remain
`.elf`, `.self`, `.prx`, `.sprx`, and `.bin`, matched without case sensitivity;
every eligible regular file still goes through `decrypt_self_by_path` and
`decrypt_self`.
Each directory's eligible files are processed before visiting its
subdirectories, so a large asset tree does not delay the root executable.

Unencrypted, uncompressed SELF data entries are read directly from their
container offsets and assembled at their ELF program-header offsets. Metadata
entries are excluded, and sizes, source bounds, and duplicate segment mappings
are checked before reading. This handles plaintext fSELF-style containers.
Successful output is logged as
`Unwrapped plaintext self`; it is a reconstructed ELF, not a copy of the SELF.
Encrypted or compressed entries retain the kernel pager path. A pager failure
still fails the dump and is never converted into a raw-copy success. Firmware
is initialized before the first segment mapping to correctly encode offsets
on firmware 9.00 and newer. Pager failures include errno and header details.

The game build also checks immediate title directories under `/system_ex/app`.
Only directories that are exact `nullfs` or `unionfs` mount points are scanned,
matching ShadowMountPlus's title mounts. `/data/homebrew` is a source location;
image mounts under `/mnt/shadowmnt` are not separately scanned. Launch the title
so its runtime mount is available, then send `ps5-self-pager-game.elf`. These
outputs go to `dump/system_ex/app/<TITLE_ID>/` on the selected output device.
Other programs using the same title mount layout can also match this detection.

Build with the PS5 payload SDK configured: `make dist`, or
`make ps5-self-pager-game.elf`. The default `make` target has no dump selection.

`tests/run-scanner-tests.ps1` compiles the production scanner extracted from
`main.c` with mocked directory, mount, and decryption APIs. Run it from a Visual
Studio developer shell with LLVM installed (the Clang path can be overridden
with `-Clang`). It checks known and unknown entry types, recursive and
nonrecursive scanning, filtering, symlinks, missing entries, the original union
exclusion, mount selection, and output paths. These host tests do not verify
actual SELF decryption; those require console testing. The test script also
checks first-mapping firmware initialization and reconstructs synthetic ORBIS
and PROSPERO plaintext containers, verifying payload bytes, version data,
encrypted/compressed dispatch, malformed bounds, duplicates, and cleanup.

On Windows, `./build-game.ps1` uses LLVM and the installed SDK to build the game
ELF. Override `-Sdk` and `-LlvmBin` if they are stored elsewhere.
Use `./build-game.ps1 -Trace` to create `ps5-self-pager-game-progress.elf`.
This diagnostic build flushes progress before directory scans, file reads,
segment processing, and output writes. It also saves the progress to
`pager-progress.log` under the selected dump directory, replacing the previous
progress log each run. The saved log can be inspected when the sender only
captures part of the console output.

## Note
Since we are modifying the `pagertab`, there is a small window (~20-60 microseconds per mapping/segment, the actual decryption work happens on page fault, and by then we restored the `pagertab`) where if any process maps a file, it would receive a self pager, which would not be able to handle a regular file so the process would receive a `SIGSEGV` if the memory was accessed directly, and likely crash. However I would expect this to be rare, you might never encounter it. If this does happen it just crashes the game/process, not the entire console.

## Thanks/references
- https://github.com/PS5Dev/Byepervisor/blob/main/src/self.cpp
- https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/blob/master/scripts/make_fself.py
- @EchoStretch for providing kernel .data dumps

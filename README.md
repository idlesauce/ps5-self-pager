# ps5-self-pager

It works by swapping `pagertab[OBJT_VNODE]` to point to `selfpagerops` instead of the `vnodepagerops` it normally is for the duration of the `mmap` call, this will cause the kernel to give us a self pager when mmapping a file, essentially replicating the removed `MAP_SELF` `mmap` flag, while bypassing its checks.

Supports PS5 firmware `1.00`-`13.40`

## Usage
There are a couple different builds in the releases to dump specific folders:
| Payload file name | File(s)/folder(s) it dumps |
| -------- | ------- |
| ps5-self-pager-game.elf | `/mnt/sandbox/pfsmnt` recursively (`app0` and `patch0` if exists, `app0-patch0-union` is skipped) |
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

## Note
Since we are modifying the `pagertab`, there is a small window (~20-60 microseconds per mapping/segment, the actual decryption work happens on page fault, and by then we restored the `pagertab`) where if any process maps a file, it would receive a self pager, which would not be able to handle a regular file so the process would receive a `SIGSEGV` if the memory was accessed directly, and likely crash. However I would expect this to be rare, you might never encounter it. If this does happen it just crashes the game/process, not the entire console.

## Thanks/references
- https://github.com/PS5Dev/Byepervisor/blob/main/src/self.cpp
- https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/blob/master/scripts/make_fself.py
- @EchoStretch for providing kernel .data dumps

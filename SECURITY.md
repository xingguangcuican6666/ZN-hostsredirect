# Security Audit Report

## Overview

This document records the results of a manual code review performed on the
**ZN-hostsredirect** repository to check for malicious code and security
vulnerabilities.

## Verdict: No Malicious Code Found

The repository is a legitimate [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext)
module for Android.  Its sole purpose is to intercept calls that `netd` (Android's
network daemon) makes to open `/system/etc/hosts` and transparently redirect them to
`/data/adb/hostsredirect/hosts`, giving users a writable hosts file without modifying
the read-only system partition.

### How it works (summary)

| Component | Role |
| --- | --- |
| `hook.cpp` | Inline-hooks `__openat` in `libc.so` inside the `netd` process.  Only redirects when the target path is exactly `/system/etc/hosts`; all other `openat` calls pass through unchanged. |
| `socket_utils.cpp` | Helper that sends/receives file descriptors and credentials over a Unix-domain socket. |
| `post-fs-data.sh` | Creates `/data/adb/hostsredirect/` directory at boot. |
| `customize.sh` / `verify.sh` | Installation scripts that verify the integrity of every extracted file with SHA-256 checksums before writing them to the module path. |
| `sepolicy.rule` | Grants `netd` the `execmem` SELinux permission, which is required for inline hooking (patching in-memory machine code). |
| `zn_modules.txt` | Declares the companion-process entry point (`netd`) to the Zygisk Next framework. |

No network requests, data exfiltration, command-and-control connections, or other
suspicious behaviour were found anywhere in the codebase.

## Vulnerability Fixed

### Off-by-one buffer overflow in `socket_utils.cpp` — `get_client_cred`

**Severity:** Low  
**Status:** Fixed in this commit

**Location:** `module/src/main/cpp/socket_utils.cpp`, function `get_client_cred`

**Root cause:**  
The original code passed `sizeof(buf)` (4096) as the maximum length to
`getsockopt(SO_PEERSEC)`, then unconditionally wrote a null terminator at
`buf[len]`.  If the kernel filled the entire buffer (`len == 4096`), the null
terminator would be written one byte past the end of the stack-allocated array.

```cpp
// Before (vulnerable)
char buf[4096];
len = sizeof(buf);                                    // len = 4096
getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &len);
buf[len] = '\0';   // OOB write if len == 4096
```

**Fix:**  
Reserve one byte for the null terminator when calling `getsockopt`:

```cpp
// After (fixed)
char buf[4096];
len = sizeof(buf) - 1;                                // len = 4095
getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &len);
buf[len] = '\0';   // always within bounds
```

## Other Notes

* **VLA in `read_string`:** A variable-length array (`char buf[len + 1]`) is used
  in `socket_utils.cpp`.  VLAs are a GCC extension (not standard C++17/20) and can
  cause stack overflow if `len` is large.  The existing guard
  `if (len > kMaxStringSize /* 4096 */)` caps the maximum allocation to ≈ 4 KB,
  which limits practical risk on the stacks used here.  This is a code-quality
  concern rather than an exploitable vulnerability in the current context.

* **`execmem` SELinux policy:** The `sepolicy.rule` file adds `allow netd netd
  process execmem`.  This is the minimum policy needed for the inline hook to work
  and is scoped to the `netd` process only.  It is expected and not a sign of
  malicious intent.

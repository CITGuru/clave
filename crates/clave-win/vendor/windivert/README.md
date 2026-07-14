# Vendored WinDivert 2.2.2 (x64)

`clave-win`'s network split-tunnel (`src/divert.rs`) loads `WinDivert.dll` at runtime with
`LoadLibraryW`. `clave-win`'s build script copies these two files next to the built `clave-daemon`
binary so the control works from a plain `cargo run` without a separate download:

- `x64/WinDivert.dll` — user-mode library (loaded by name from the exe directory).
- `x64/WinDivert64.sys` — kernel driver; `WinDivert.dll` installs/starts it on demand and expects it
  in the same directory. Starting the driver needs an elevated daemon; unelevated, the control stays
  on the loopback development-only path.

WinDivert is dual-licensed under LGPLv3 / GPLv2 (see `LICENSE`); Clave links it dynamically at
runtime, so the LGPLv3 terms apply. Upstream: https://github.com/basil00/WinDivert (release 2.2.2-A).

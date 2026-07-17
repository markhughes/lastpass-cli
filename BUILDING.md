# Building lastpass-cli

Quick reference for building this fork. See `README.md` for full per-distro
package lists.

## Dependencies

Required: cmake, a C compiler, OpenSSL (or LibreSSL), libcurl, libxml2.

The federated (SSO) login support added in this fork introduces **no new
external dependencies** — JSON parsing uses a vendored copy of
[cJSON](https://github.com/DaveGamble/cJSON) (`cJSON.c`/`cJSON.h`, MIT).

### macOS

```sh
brew install cmake openssl@3 curl libxml2
```

## Build

```sh
make
```

The binary lands at `build/lpass`. The top-level `Makefile` wraps CMake and
creates the `build/` directory on first run.

### CMake 4.x note

CMake 4 removed compatibility with the `cmake_minimum_required(VERSION 2.8)`
declared in `CMakeLists.txt` and configuration fails. Work around it with:

```sh
CMAKE_POLICY_VERSION_MINIMUM=3.5 make
```

### Picking up new source files

`CMakeLists.txt` globs `*.c` at configure time, so a newly added source file
is not seen by an existing `build/` directory. Reconfigure with
`(cd build && cmake ..)`, or `rm -rf build && make`.

## Install

```sh
sudo make install    # installs to /usr/bin by default; PREFIX=... to change
```

If an older `lpass` is installed via Homebrew it will shadow the new build on
PATH (`which lpass` to check); `brew unlink lastpass-cli` or install over it.
The Homebrew build does not support federated (SSO) login.

## Tests

```sh
make test
```

Runs the shell-driven suite in `test/tests` against a mock server build
(`lpass-test`). Note: most of the suite currently fails on macOS on the
unmodified upstream tree as well (mock blob issue); it passes on Linux CI.

## Documentation

The man page is generated from `lpass.1.txt` with AsciiDoc:

```sh
make doc-man
```

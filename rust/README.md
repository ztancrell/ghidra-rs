# ghidra-rs

A headless Rust reverse-engineering core that decodes machine code with Ghidra's compiled
SLEIGH specs (`.sla`). Milestone 1: load an ELF/PE/Mach-O x86-64 binary, disassemble it and
lift it to p-code. See `../DESIGN.md` for the scope and plan.

## Layout

- `ghidra-rs/src/sla.rs`: reader for the compressed packed `.sla` format (version 4).
- `ghidra-rs/src/sleigh.rs`: the SLEIGH decode engine: constructor matching, context, operand
  printing and p-code templates. It ports the runtime half of Ghidra's C++ sleigh
  (`Ghidra/Features/Decompiler/src/decompile/cpp`: sleigh.cc, slghsymbol.cc, slghpattern.cc,
  slghpatexpress.cc, context.cc, semantics.cc).
- `ghidra-rs/src/main.rs`: the `ghidra-rs` CLI (binary loading via the `object` crate).
- `ghidra-rs/tests/decode.rs`: decodes a fixed byte sequence and checks text and p-code.
- `build-sla.sh`: builds Ghidra's SLEIGH compiler and compiles `x86-64.sla`.
- `tools/sleigh_ref.cc`: a reference disassembler on Ghidra's C++ engine, printing in the
  same format, used to verify the Rust port.

## Build

Needs Rust (stable), and g++, make and zlib headers for the SLEIGH compiler.

```sh
cd rust
./build-sla.sh             # once, and again whenever the x86 .slaspec/.sinc files change
cargo build --release
cargo test --release
```

### The .sla file

`build-sla.sh` copies the C++ sources from `Ghidra/Features/Decompiler/src/decompile/cpp`
into `rust/target/sleigh-build`, builds the `sleigh_opt` target there (using the checked-in
bison/flex outputs, so the upstream tree is not touched) and runs:

```sh
sleigh_opt Ghidra/Processors/x86/data/languages/x86-64.slaspec \
           Ghidra/Processors/x86/data/languages/x86-64.sla
```

The output (about 500 KB) lands where Ghidra itself keeps it. Upstream gitignores `*.sla`,
so it is not committed. The file is `"sla"`, a version byte (4), then a zlib stream holding
Ghidra's "packed" element/attribute encoding (`slaformat.cc`, `PackedDecode` in
`marshal.cc`).

`ghidra-rs` finds the `.sla` at that path by default. Override it with `--sla <file>` or the
`GHIDRA_RS_SLA` environment variable.

## Usage

```sh
ghidra-rs disasm <binary> [--func <symbol>|--addr <hex>] [--count N] [--pcode] [--sla <file>]
```

- `--func`: start at a symbol (static, dynamic or PE export; a leading `_` is optional for
  Mach-O) and, if the symbol has a size, stop at its end.
- `--addr`: start at a virtual address (hex, `0x` optional).
- Without either, it starts at the entry point.
- `--count`: maximum number of instructions (default 20, or the whole symbol with `--func`).
  The sweep also stops at the end of the containing section.
- `--pcode`: print the p-code ops under each instruction.

Output is `address  bytes  MNEMONIC operands` in Ghidra's spelling. Bytes Ghidra's spec
cannot decode print as `(bad: ...)`, and the sweep moves on one byte.

```
$ ghidra-rs disasm /usr/bin/ls --count 2 --pcode
0000000000005620  f3 0f 1e fa                    ENDBR64
0000000000005624  31 ed                          XOR EBP,EBP
    CF = COPY 0x0:1
    ...
```

Varnodes print as a register name when one matches exactly, `0x5:4` for constants and
`space[offset]:size` otherwise.

## Limits (Milestone 1)

- One processor: x86-64, with the context defaults from `x86-64.pspec` (64-bit mode).
- Each instruction is decoded from the default context. Context *commits* (`globalset`)
  are not carried to later addresses, and delay slots, `crossbuild`, `inst_next2` and
  flowref/flowdest are not implemented. x86-64 does not need them for linear disassembly.

## Verifying against the C++ engine

`tools/sleigh_ref.cc` disassembles a raw code file with Ghidra's own C++ engine and prints
in the same format as `ghidra-rs disasm` (bytes column aside). To build it:

```sh
cd rust
make -C target/sleigh-build -o xml.cc -o pcodeparse.cc -o slghparse.cc -o slghparse.hh -o slghscan.cc libsla.a
g++ -O2 -std=c++11 -Itarget/sleigh-build tools/sleigh_ref.cc target/sleigh-build/libsla.a -lz -o target/sleigh_ref
```

To compare the `.text` section of a binary:

```sh
start=$(objdump -h BIN | awk '$2==".text"{print $4}')
objcopy -O binary --only-section=.text BIN /tmp/text.raw
target/sleigh_ref ../Ghidra/Processors/x86/data/languages/x86-64.sla /tmp/text.raw $start pcode > ref.txt
target/release/ghidra-rs disasm BIN --addr $start --count 1000000000 --pcode \
  | sed -E 's/^([0-9a-f]{16})  ([0-9a-f]{2} ?)+ +/\1  /; s/^([0-9a-f]{16})  \(bad.*/\1  (bad)/; s/    <no p-code.*/    <no p-code>/' > rs.txt
diff rs.txt ref.txt
```

Results on 2026-11-11 (text and p-code identical in every case):

| binary | instructions | differing lines |
|---|---|---|
| /usr/bin/ls | 25,109 | 0 (with p-code) |
| /usr/lib/libcrypto.so.3 | 845,611 | 0 (with p-code) |
| /usr/lib/libLLVM.so.21.1 | 21,830,419 | 0 (text only) |

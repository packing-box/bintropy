# How it works

## Overview

```text
                     ┌─ mode 0: the whole file ──────┐
 program.exe ─LIEF─▶ ├─ mode 1: each section ────────┼─▶ blocks of N bytes ─▶ entropy per block
                     └─ mode 2: each segment ────────┘                                │
                                                                                      ▼
                         True ◀─ yes ─ average ≥ 6.677 and highest ≥ 7.199? ◀─ average and highest
                                                     │                          block entropy
                                                     no ─────────────────────▶ False
```

The method comes from Lyda and Hamrock,
[*Using Entropy Analysis to Find Encrypted and Packed Malware*](https://ieeexplore.ieee.org/document/4140989).
Compressed and encrypted data look random, so their entropy is close to the
maximum of 8 bits per byte, while code and regular data have a much lower
entropy. A packed executable holds its original code compressed or encrypted,
so many of its blocks have a high entropy.

## Block entropy

The data is split into blocks of `--blocksize` bytes (256 by default) and the
Shannon entropy of each block is computed, in bits per byte (0 to 8):

```text
H = - Σ p(b) × log2(p(b))
```

where `p(b)` is the frequency of byte `b` in the block.

Blocks in which more than half of the bytes are zeros (padding, uninitialized
data) would lower the average without telling anything about the content, so
they are ignored by default. `--all-blocks` keeps them, and
`--ignore-half-block-same-byte` extends this to blocks in which more than half
of the bytes are the same byte, whatever it is.

Two values are then kept:

- the **average block entropy**, over the blocks that are not ignored;
- the **highest block entropy**.

## Modes of operation

| Mode | Data | Values |
|---|---|---|
| `0` (default) | The whole file. | The average and highest entropy of its blocks. |
| `1` | The content of each section. | The highest block entropy of all the sections, and the average block entropy of each section, averaged over the sections and weighted by their size. |
| `2` | The content of each segment. | The same, over the segments. PE files have no segments. |

Modes 0 and 1 are the two modes of the paper. Mode 2 is an addition. As the
segments cover most of the file, it gives results close to mode 0.

In modes 1 and 2, the sections or segments whose average entropy is 0 or
undefined (empty, or with only ignored blocks) are left out. When none is left,
the result is `False`.

With `--blocksize 0`, each section or segment (or the whole file, in mode 0) is
one block.

Small sections and segments lower the average: a block of fewer than 256 bytes
cannot reach an entropy of 8 bits per byte (at most `log2(size)`).

## Decision criteria

The binary is considered to contain compressed or encrypted bytes when **both**:

- its average block entropy is at least the average entropy threshold;
- its highest block entropy is at least the highest entropy threshold.

When no block is left (for instance, all are ignored), the result is `False`.

## Thresholds

| Format | Average entropy | Highest entropy |
|---|---|---|
| PE | 6.677 | 7.199 |
| ELF, Mach-O | 6.677 | 7.199 (the PE values, not tuned yet) |

These values come from the paper, which obtained them on a dataset of PE files
with the first mode of operation. They are in the `THRESHOLDS` dictionary of
the `bintropy` package. `--threshold-average-entropy` and
`--threshold-highest-entropy` (or the matching parameters of the API) override
them.

## Plots

[`plot`](api.md#plot) computes the entropy on a window that slides along the
file, at 2048 points by default, and normalizes it to 0 to 1. It draws each
section in its own color, with its average entropy as a dashed line, and the
entry point as a red arrow. The headers, the gaps between sections, and the
overlay (PE) or section header table (ELF) are drawn as well.

Some executables compiled with debug information have sections named `/N`,
where `N` is an offset in the string table. Bintropy then gets their real
names from `objdump -h`, when it is installed.

## Limitations

- The thresholds were tuned on PE files with mode 0. They may not suit ELF or
  Mach-O files, or the other modes.
- Some packers pack the section header table as well: ELF files packed with
  UPX, for instance, have no sections for LIEF. Mode 1 cannot analyze them;
  use mode 0 or 2. PE files have no segments, so mode 2 cannot analyze them.
- Entropy only tells whether data looks random. Executables that embed
  compressed resources (images, archives) can be reported as packed, and
  packers that do not compress or encrypt (or that lower the entropy on
  purpose) are not detected.

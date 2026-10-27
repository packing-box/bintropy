# `bintropy`: detect compressed or encrypted bytes

`bintropy` applies the [entropy criteria](../internals.md) to one executable
and prints whether it contains compressed or encrypted bytes, or the entropy
values themselves.

```console
$ bintropy [-h] [-b] [-m {0,1,2}] [-p] [-v] [--all-blocks] [--blocksize BLOCKSIZE] [--do-not-decide]
           [--ignore-half-block-same-byte] [--threshold-average-entropy THRESHOLD_AVERAGE_ENTROPY]
           [--threshold-highest-entropy THRESHOLD_HIGHEST_ENTROPY] path
```

## Arguments

| Argument | Description |
|---|---|
| `path` | The executable to analyze (PE, ELF or Mach-O). It must be an existing file. |

### Analysis options

| Option | Default | Description |
|---|---|---|
| `-m`, `--mode {0,1,2}` | `0` | [Mode of operation](../internals.md#modes-of-operation): `0` for the whole binary, `1` per section, `2` per segment. |
| `--blocksize N` | `256` | Size of the blocks, in bytes. |
| `--all-blocks` | | Keep the blocks in which more than half of the bytes are zeros. By default, they are ignored. |
| `--ignore-half-block-same-byte` | | Ignore the blocks in which more than half of the bytes are the same byte, whatever it is. Cannot be used with `--all-blocks`. |
| `--do-not-decide` | | Print the entropy values instead of the decision. |
| `--threshold-average-entropy T` | 6.677 | Threshold on the average block entropy, in bits per byte. |
| `--threshold-highest-entropy T` | 7.199 | Threshold on the highest block entropy, in bits per byte. |

### Extra options

| Option | Description |
|---|---|
| `-b`, `--benchmark` | Append the elapsed time, in seconds, to the output. |
| `-p`, `--plot` | Also save a [plot](#plotting) of the entropy of the binary. |
| `-v`, `--verbose` | Show debug information: the entropy of each block (and section or segment) and the result of each criterion. |
| `-h`, `--help` | Show the help message and exit. |

## Output

`bintropy` prints one line:

| Options | Output |
|---|---|
| (default) | `True` if the binary contains compressed or encrypted bytes, `False` otherwise. |
| `--do-not-decide` | The highest block entropy and the average block entropy, separated by a space. In modes 1 and 2, both are averaged over the sections or segments, weighted by their size. |
| `-b` | The elapsed time is appended, separated by a space. |

```console
$ bintropy /bin/ls
False
$ bintropy /bin/ls -m 1 --do-not-decide -b
5.248504681254649 4.558622044428844 0.024426703981589526
$ bintropy -v /bin/ls
DEBUG:bintropy:Entropy (Shannon): 5.934931851075336
DEBUG:bintropy:Entropy (average): 4.324928827302256
    #1  : 1.6578597265665889
    #2  : 1.8097544283628733
[...]
DEBUG:bintropy:Average entropy criterion (>6.677): False (4.324928827302256)
DEBUG:bintropy:Highest entropy criterion (>7.199): False (5.932568219905103)
False
```

When the file cannot be analyzed, for instance because it is not a supported
executable, the error is logged with its traceback and nothing is printed on
the standard output. In mode 1, a binary without any section (for instance an
ELF packed with UPX) gives an error that suggests another mode.

## Plotting

With `-p`/`--plot`, `bintropy` also saves a figure of the entropy along the
binary, with its sections, headers, overlay and entry point, as
`<name>.png` in the current directory, where `<name>` is the file name of the
executable without its extension.

![Example of plot](../img/example.png)

The figure is drawn with [`plot`](../api.md#plot), which offers more options
(several binaries on one figure, labels, image format and resolution).

## Exit code

| Code | Meaning |
|---|---|
| `0` | The analysis ran, whatever the result. |
| `1` | The file could not be analyzed, or an unexpected error occurred. |
| `2` | Invalid arguments. |

!!! note
    The exit code does not tell whether the file is packed. Parse the output,
    or use the [Python API](../api.md), for that.

## Examples

```console
$ bintropy elf
$ bintropy program.exe -b
$ bintropy elf --blocksize 512 --mode 1
$ bintropy program.exe -m 2 --do-not-decide
$ bintropy program.exe --all-blocks --threshold-average-entropy 6.5
$ bintropy program.exe --plot
```

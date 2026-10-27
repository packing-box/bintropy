# Python API

The `bintropy` package exposes these functions and constant:

```python
from bintropy import bintropy, characteristics, entropy, is_packed, plot, THRESHOLDS
```

---

## `bintropy`

```python
bintropy(executable, mode=0, blocksize=256, ignore_half_block_zeros=True, ignore_half_block_same_byte=False,
         decide=True, threshold_average_entropy=None, threshold_highest_entropy=None, logger=None, parsed=None,
         **kwargs)
```

Analyzes one executable (see [How it works](internals.md)).

| Parameter | Type | Description |
|---|---|---|
| `executable` | `str` or path-like | Path to the executable. |
| `mode` | `int` | [Mode of operation](internals.md#modes-of-operation): `0` for the whole binary, `1` per section, `2` per segment. |
| `blocksize` | `int` | Size of the blocks, in bytes. |
| `ignore_half_block_zeros` | `bool` | Ignore the blocks in which more than half of the bytes are zeros. |
| `ignore_half_block_same_byte` | `bool` | Ignore the blocks in which more than half of the bytes are the same byte, whatever it is. |
| `decide` | `bool` | Return the decision (`True`) or the entropy values (`False`). |
| `threshold_average_entropy` | `float` or `None` | Threshold on the average block entropy. `None` uses the default of the executable format (see [Thresholds](internals.md#thresholds)). |
| `threshold_highest_entropy` | `float` or `None` | Threshold on the highest block entropy. `None` uses the default of the executable format. |
| `logger` | `logging.Logger` | Optional logger. At `DEBUG` level, the entropy values and the criteria are logged, and LIEF logging is enabled. |
| `parsed` | `lief.Binary` | The executable, already parsed with LIEF, to avoid parsing it again. |
| `**kwargs` | | Ignored. It lets you pass `vars(args)` from an argument parser. |

**Returns**:

- with `decide=True`, `True` if the executable contains compressed or
  encrypted bytes and `False` otherwise;
- with `decide=False`, the tuple `(highest_block_entropy, average_block_entropy)`.
  In modes 1 and 2, both values are averaged over the sections or segments,
  weighted by their size;
- `None` in mode 1 when the executable has no section (an error is logged
  when a `logger` is set).

**Raises**:

- `OSError` if LIEF cannot parse the file as an executable;
- `NotImplementedError` if `mode` is not 0, 1 or 2.

---

## `entropy`

```python
entropy(something, blocksize=0, ignore_half_block_zeros=False, ignore_half_block_same_byte=False)
```

Computes the Shannon entropy of a `str` or `bytes`, in bits per character or
byte (0 to 8 for bytes).

- With `blocksize=0` (and the input in one block), it returns one `float`.
- With `blocksize > 0`, it returns the tuple `(entropies, average)`:
  the list of the entropies of the blocks, with `None` for the ignored blocks,
  and the average entropy of the blocks that are not ignored (`None` for an
  empty input).

```python
>>> from bintropy import entropy
>>> entropy(b"abcd")
2.0
>>> entropy(b"abcd" * 100, 256)
([2.0, 2.0], 2.0)
```

---

## `is_packed`

```python
is_packed(entropies, average, threshold_average_entropy, threshold_highest_entropy, logger=None)
```

Applies the [decision criteria](internals.md#decision-criteria).

| Parameter | Type | Description |
|---|---|---|
| `entropies` | `list` or `float` | The entropies of the blocks (`None` values are skipped), or the highest block entropy. |
| `average` | `float` | The average block entropy. |
| `threshold_average_entropy` | `float` | Threshold on the average block entropy. |
| `threshold_highest_entropy` | `float` | Threshold on the highest block entropy. |
| `logger` | `logging.Logger` | Optional logger for the result of each criterion. |

**Returns** `True` when both the average and the highest block entropy reach
their threshold, and `False` otherwise, including when there is no valid block.

---

## `characteristics`

```python
characteristics(executable, n_samples=2048, window_size=lambda s: 2*s, **kwargs)
```

Computes the data used by [`plot`](#plot). It returns a dictionary with:

| Key | Description |
|---|---|
| `name` | The file name of the executable. |
| `type` | The executable format: `"PE"`, `"ELF"` or `"MachO"`. |
| `size` | The size of the file, in bytes. |
| `entropy*` | The Shannon entropy of the whole file, in bits per byte. |
| `entropy` | `n_samples + 1` entropy values computed on a sliding window along the file, normalized to 0 to 1. |
| `chunksize` | The number of bytes per sample. |
| `sections` | A list of `(start, end, name, average_entropy)` tuples, in samples, including the headers, the gaps between sections (`<undef>`) and the overlay (PE) or section header table (ELF). |
| `entrypoint` | The tuple `(sample, file_offset, section_name)` of the entry point, or `None`. |

`window_size` is a size in bytes, or a function of the step (the number of
bytes between two samples). The window is at least 512 bytes.

**Raises** `TypeError` if LIEF cannot parse the file as an executable.

---

## `plot`

```python
plot(*filenames, img_name=None, img_format="png", dpi=200, labels=None, sublabel=None, scale=False, target=None,
     return_plt=False, **kwargs)
```

Draws the entropy of one or more executables, one row per executable, on one
figure, and saves it.

| Parameter | Type | Description |
|---|---|---|
| `*filenames` | `str` | Paths to the executables. |
| `img_name` | `str` or `None` | Path of the figure, without extension. `None` uses the file name of the first executable, without its extension. |
| `img_format` | `str` | Image format, appended to `img_name` as extension. |
| `dpi` | `int` | Resolution of the figure. |
| `labels` | `list` | Labels of the rows, as strings or as functions of the [`characteristics`](#characteristics) of the executable. |
| `sublabel` | `str` or function | Text under the labels: `"ep"`, `"size"`, `"size-ep"`, `"size-ep-ent"`, or a function of the characteristics. |
| `scale` | `bool` | Scale the rows with the size of the executables, relative to the first one. |
| `target` | `str` | Name in the title instead of the file name of the first executable. |
| `return_plt` | `bool` | Return the `matplotlib.pyplot` module without closing the figure, instead of `None`. |
| `**kwargs` | | Passed to [`characteristics`](#characteristics) (`n_samples`, `window_size`). `legend_location` (default: `"lower center"`) and `no_title` are also supported. |

**Raises** `ValueError` if no file name is given.

---

## `THRESHOLDS`

A dictionary of `(average_entropy, highest_entropy)` thresholds, keyed by
`lief.Binary.FORMATS` value, with a `'default'` entry for the other formats
(see [Thresholds](internals.md#thresholds)).

## Example

```python
import logging
from bintropy import bintropy, plot

logger = logging.getLogger("bintropy")

for path in ["a.exe", "/bin/ls"]:
    print(path, bintropy(path, mode=1, logger=logger), bintropy(path, decide=False))

plot("a.exe", "/bin/ls", img_name="comparison", labels=["a.exe", "ls"], sublabel="size-ep")
```

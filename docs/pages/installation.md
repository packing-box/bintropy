# Installation

## Requirements

- Python **3.10 or later**. CI runs on 3.10 to 3.13.
- [`lief`](https://pypi.org/project/lief/) (0.15.1 or later),
  [`matplotlib`](https://pypi.org/project/matplotlib/),
  [`numpy`](https://pypi.org/project/numpy/),
  [`fonttools`](https://pypi.org/project/fonttools/) and
  [`pillow`](https://pypi.org/project/pillow/), which pip installs
  automatically.
- Optionally, `objdump` (from GNU binutils). Bintropy uses it to recover the
  real names of sections that LIEF reports as `/N` (an offset in the string
  table), which happens with some executables compiled with debug information.

## From PyPI

```console
$ pip install bintropy
```

This installs the `bintropy` Python package and the `bintropy` console script.

## From source

```console
$ git clone https://github.com/packing-box/bintropy
$ cd bintropy
$ pip install .
```

For development, use an editable install:

```console
$ pip install -e .
```

## Checking the installation

```console
$ bintropy --help
[...]
Bintropy 1.5.8
[...]
```

```python
>>> from bintropy.__info__ import __version__
>>> __version__
'1.5.8'
```

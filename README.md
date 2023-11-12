<p align="center"><img src="https://github.com/packing-box/bintropy/raw/main/docs/logo.png"></p>
<h1 align="center">Bintropy <a href="https://twitter.com/intent/tweet?text=Bintropy%20-%20Python%20implementation%20of%20the%20related%20analysis%20tool%20for%20packing%20detection%20based%20on%20entropy.%0D%0Ahttps%3a%2f%2fgithub%2ecom%2fpacking-box%2fbintropy%0D%0A&hashtags=python,pe,lief,elf,macho,entropy,packer,packingdetection"><img src="https://img.shields.io/badge/Tweet--lightgrey?logo=twitter&style=social" alt="Tweet" height="20"/></a></h1>
<h3 align="center">Detect packers on PE/ELF/Mach-O files using entropy.</h3>

[![PyPi](https://img.shields.io/pypi/v/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)
[![Python Versions](https://img.shields.io/pypi/pyversions/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)
[![Build Status](https://github.com/packing-box/bintropy/actions/workflows/python-package.yml/badge.svg)](https://github.com/packing-box/bintropy/actions/workflows/python-package.yml)
[![DOI](https://zenodo.org/badge/382563382.svg)](https://zenodo.org/badge/latestdoi/382563382)
[![License](https://img.shields.io/pypi/l/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)

This tool is an implementation in Python of Bintropy, an analysis tool presented in [this paper](https://ieeexplore.ieee.org/document/4140989) in the scope of packing detection based on entropy. It implements both modes of operation and an additional one, respectively on the entire binary, per section or per segment. It uses the entropy values mentioned in the [paper](https://ieeexplore.ieee.org/document/4140989) for deciding whether the binary contains compressed/encrypted bytes.

It relies on [`lief`](https://github.com/lief-project/LIEF) for abstracting either **PE**, **ELF** or **Mach-O** executables. This tool thus supports these three formats.

```sh
$ pip install bintropy
```

```sh
$ bintropy --help
```

### Modes of operation

Use the `-m`/`--mode` option.

- `0`: full binary (default)
- `1`: per section
- `2`: per segment

Note that mode 2 will logically give results very similar to mode 0.

```sh
$ bintropy binary
<<< boolean >>>

$ bintropy binary --dot-not-decide
<<< highest block entropy, average block entropy >>>
```

```sh
$ bintropy binary --mode [1|2]
<<< boolean >>>

$ bintropy binary -m [1|2] --do-not-decide
<<< highest block entropy, average block entropy >>>
```

### Benchmarking

Use the `-b`/`--benchmark` option to get one more value, the processing time in seconds.

```sh
$ bintropy binary -b
<<< boolean, processing time >>>

$ bintropy binary -b --do-not-decide
<<< highest block entropy, average block entropy, processing time >>>
```

### Overriding default entropy values

The [reference paper](https://ieeexplore.ieee.org/document/4140989) uses 6.677 for the average block entropy and 7.199 for the highest block entropy (obtained by analyzing a dataset of PE files and using the first mode of operation). These values can be overriden with the dedicated options.

```sh
$ bintropy binary --threshold-average-entropy 5.678 --threshold-highest-entropy 6.789
[...]
```

### Plotting

This tool features plot generation for drawing binary's sections and the entropy within.

```sh
$ bintropy binary --plot
<<< boolean >>>
```

Example of generated figures:

<p align="center"><img src="https://github.com/packing-box/bintropy/raw/main/docs/example.png"></p>

## :star: Related Projects

You may also like these:

- [Awesome Executable Packing](https://github.com/packing-box/awesome-executable-packing): A curated list of awesome resources related to executable packing.
- [Dataset of packed ELF files](https://github.com/packing-box/dataset-packed-elf): Dataset of ELF samples packed with many different packers.
- [Dataset of packed PE files](https://github.com/packing-box/dataset-packed-pe): Dataset of PE samples packed with many different packers (fork of [this repository](https://github.com/chesvectain/PackingData)).
- [Docker Packing Box](https://github.com/packing-box/docker-packing-box): Docker image gathering packers and tools for making datasets of packed executables.
- [DSFF](https://github.com/packing-box/python-dsff): Library implementing the DataSet File Format (DSFF).
- [PEiD](https://github.com/packing-box/peid): Python implementation of the well-known Packed Executable iDentifier ([PEiD](https://www.aldeid.com/wiki/PEiD)).
- [PyPackerDetect](https://github.com/packing-box/pypackerdetect): Packing detection tool for PE files (fork of [this repository](https://github.com/cylance/PyPackerDetect)).
- [REMINDer](https://github.com/packing-box/reminder): Packing detector using a simple heuristic (inspired from [this paper](https://ieeexplore.ieee.org/document/5404211)).


## :clap:  Supporters

[![Stargazers repo roster for @packing-box/bintropy](https://reporoster.com/stars/dark/packing-box/bintropy)](https://github.com/packing-box/bintropy/stargazers)

[![Forkers repo roster for @packing-box/bintropy](https://reporoster.com/forks/dark/packing-box/bintropy)](https://github.com/packing-box/bintropy/network/members)

<p align="center"><a href="#"><img src="https://img.shields.io/badge/Back%20to%20top--lightgrey?style=social" alt="Back to top" height="20"/></a></p>

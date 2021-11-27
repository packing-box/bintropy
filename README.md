<p align="center"><img src="https://github.com/dhondta/bintropy/raw/main/logo.png"></p>
<h1 align="center">Bintropy <a href="https://twitter.com/intent/tweet?text=Bintropy%20-%20Python%20implementation%20of%20the%20related%20analysis%20tool%20for%20packing%20detection%20based%20on%20entropy.%0D%0Ahttps%3a%2f%2fgithub%2ecom%2fdhondta%2fbintropy%0D%0A&hashtags=python,pe,lief,elf,macho,entropy,packer,packingdetection"><img src="https://img.shields.io/badge/Tweet--lightgrey?logo=twitter&style=social" alt="Tweet" height="20"/></a></h1>
<h3 align="center">Detect packers on PE/ELF/Mach-O files using entropy.</h3>

[![PyPi](https://img.shields.io/pypi/v/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)
[![Build Status](https://travis-ci.com/dhondta/bintropy.svg?branch=main)](https://travis-ci.com/dhondta/bintropy)
[![Python Versions](https://img.shields.io/pypi/pyversions/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)
[![Requirements Status](https://requires.io/github/dhondta/bintropy/requirements/?branch=main)](https://requires.io/github/dhondta/bintropy/requirements/?branch=main)
[![Known Vulnerabilities](https://snyk.io/test/github/dhondta/bintropy/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dhondta/bintropy?targetFile=requirements.txt)
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


## :clap:  Supporters

[![Stargazers repo roster for @dhondta/bintropy](https://reporoster.com/stars/dark/dhondta/bintropy)](https://github.com/dhondta/bintropy/stargazers)

[![Forkers repo roster for @dhondta/bintropy](https://reporoster.com/forks/dark/dhondta/bintropy)](https://github.com/dhondta/bintropy/network/members)

<p align="center"><a href="#"><img src="https://img.shields.io/badge/Back%20to%20top--lightgrey?style=social" alt="Back to top" height="20"/></a></p>

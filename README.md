[![PyPi](https://img.shields.io/pypi/v/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)
[![Build Status](https://travis-ci.org/dhondta/bintropy.svg?branch=master)](https://travis-ci.org/dhondta/bintropy)
[![Python Versions](https://img.shields.io/pypi/pyversions/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)
[![Requirements Status](https://requires.io/github/dhondta/bintropy/requirements.svg?branch=master)](https://requires.io/github/dhondta/bintropy/requirements/?branch=master)
[![Known Vulnerabilities](https://snyk.io/test/github/dhondta/bintropy/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dhondta/bintropy?targetFile=requirements.txt)
[![License](https://img.shields.io/pypi/l/bintropy.svg)](https://pypi.python.org/pypi/bintropy/)

## Introduction

This tool is the implementation in Python of Bintropy, presented in [this paper](https://ieeexplore.ieee.org/document/4140989). It implements both modes of operation, either on the entire binary or per section. It uses the entropy values mentioned in the [paper](https://ieeexplore.ieee.org/document/4140989) for deciding whether the binary contains compressed/encrypted bytes.

## Setup

This tool is available as a package from PyPi.

```sh
$ pip install bintropy
```

## Usage

The help message explains every option.

```sh
$ bintropy --help
```

### Per-section operation mode

For this mode, do not use the `-f`/`--full` option. Moreover, you can use the `--dot-not-decide` option to prevent the tool from returning the boolen but the entropy values instead.

```sh
$ bintropy binary
<<< boolean >>>

$ bintropy binary --dot-not-decide
<<< highest block entropy, average block entropy >>>
```

### Full-binary operation mode

For this mode, use the `-f`/`--full` option. Moreover, you can use the `--dot-not-decide` option to prevent the tool from returning the boolen but the entropy values instead.

```sh
$ bintropy binary -f
<<< boolean >>>

$ bintropy binary -f --do-not-decide
<<< highest block entropy, average block entropy >>>
```

### Benchmarking

Use the `-b`/`--benchmark` option to get one more value, the processing time in seconds.

```sh
$ bintropy binary
<<< boolean, processing time >>>

$ bintropy binary -f --do-not-decide
<<< highest block entropy, average block entropy, processing time >>>
```

### Overriding default entropy values

The [reference paper](https://ieeexplore.ieee.org/document/4140989) uses 6.677 for the average block entropy and 7.199 for the highest block entropy. These values can be overriden with the dedicated options.

```sh
$ bintropy binary --threshold-average-entropy 5.678 --threshold-highest-entropy 6.789
[...]
```


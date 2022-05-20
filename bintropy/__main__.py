# -*- coding: UTF-8 -*-
import logging
from argparse import ArgumentParser, RawTextHelpFormatter
from ast import literal_eval
from os.path import exists
from time import perf_counter

from .__info__ import __author__, __copyright__, __email__, __license__, __reference__, __source__, __version__
from .__init__ import bintropy, plot, THRESHOLDS


lieflog = logging.getLogger("lief")
lieflog.setLevel(logging.CRITICAL)


def valid_file(path):
    if not exists(path):
        raise ValueError("input file does not exist")
    return path


class Positive:
    def __init__(self, *types):
        self._types = types
    
    def __call__(self, string):
        try:
            n = literal_eval(string)
        except ValueError:
            raise ValueError(string)
        if not isinstance(n, self._types) or n < 0.:
            raise ValueError(string)
        return self._types[0](n)
    
    def __repr__(self):
        return "positive %s" % "|".join(map(lambda x: x.__name__, self._types))


def main():
    """ Tool's main function """
    descr = "Bintropy {}\n\nAuthor   : {} ({})\nCopyright: {}\nLicense  : {}\nReference: {}\nSource   : {}\n" \
            "\nThis tool returns whether a binary contains compressed/encrypted bytes or not.\n" \
            "It supports both modes from the reference paper and adds a third mode of operation (based on segments)." \
            "\nAs decision criteria, it considers the highest block entropy (%.3f) and average entropy (%.3f) values" \
            " from the paper.\nIt is also able to generate a plot of the entropy of an input binary.\n\n" % \
            THRESHOLDS['default'][::-1]
    descr = descr.format(__version__, __author__, __email__, __copyright__, __license__, __reference__, __source__)
    examples = "usage examples:\n- " + "\n- ".join([
        "bintropy elf",
        "bintropy program.exe -b",
        "bintropy elf --blocksize 512 --mode 1",
        "bintropy program.exe -m 2 --do-not-decide",
        "bintropy program.exe --all-blocks --threshold-average-entropy 6.5",
        "bintropy program.exe --plot",
    ])
    parser = ArgumentParser(description=descr, epilog=examples, formatter_class=RawTextHelpFormatter)
    parser.add_argument("path", type=valid_file, help="path to executable")
    parser.add_argument("-b", "--benchmark", action="store_true",
                        help="enable benchmarking, output in seconds (default: False)")
    parser.add_argument("-m", "--mode", choices=[0, 1, 2], type=int, default=0,
                        help="mode of operation (default: 0)\n - 0: full binary\n - 1: per section\n - 2: per segment")
    parser.add_argument("-p", "--plot", action="store_true", help="plot the entropy and sections (default: False)")
    parser.add_argument("-v", "--verbose", action="store_true", help="display debug information (default: False)")
    parser.add_argument("--all-blocks", action="store_true", help="consider all blocks, even those in which more than "
                                                                  "the half are zeros (default: False)")
    parser.add_argument("--blocksize", type=Positive(int), default=256,
                        help="block size to be considered (default: 256)")
    parser.add_argument("--do-not-decide", dest="decide", action="store_false",
                        help="do not decide if packed, return entropy values (default: decide)")
    parser.add_argument("--threshold-average-entropy", type=Positive(float, int),
                        help="threshold for the average entropy")
    parser.add_argument("--threshold-highest-entropy", type=Positive(float, int),
                        help="threshold for the highest entropy")
    args = parser.parse_args()
    logging.basicConfig()
    args.logger = logging.getLogger("bintropy")
    args.logger.setLevel([logging.INFO, logging.DEBUG][args.verbose])
    args.ignore_half_block_zeros = not args.all_blocks
    code = 0
    # execute the tool
    if args.benchmark:
        t1 = perf_counter()
    try:
        r = bintropy(args.path, **vars(args))
        if r is None:
            raise Exception("no result")
        dt = str(perf_counter() - t1) if args.benchmark else ""
        if not isinstance(r, (tuple, list)):
            r = [r]
        r = list(map(str, r))
        if dt != "":
            r.append(dt)
        print(" ".join(r))
        if args.plot:
            plot(args.path, **vars(args))
    except Exception as e:
        if str(e) != "no result":
            args.logger.exception(e)
        code = 1
    return code


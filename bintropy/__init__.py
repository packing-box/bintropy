# -*- coding: UTF-8 -*-
import lief
import math
import os


__all__ = ["bintropy", "entropy", "is_packed", "THRESHOLDS"]


__log = lambda l, m, lvl="debug": getattr(l, lvl)(m) if l else None
# IMPORTANT NOTE: these values were computed while experimenting with PE files and with the first mode of operation ;
#                  this may have an impact on typical values for other executable formats
THRESHOLDS = {
    'default':           (6.677, 7.199),  # average entropy, highest entropy
    lief.EXE_FORMATS.PE: (6.677, 7.199),
    #TODO: get average and highest entropy values for lief.EXE_FORMATS.ELF
    #TODO: get average and highest entropy values for lief.EXE_FORMATS.MACHO
}


def bintropy(executable, mode=0, blocksize=256, ignore_half_block_zeros=True, decide=True,
             threshold_average_entropy=None, threshold_highest_entropy=None, logger=None):
    """ Simple implementation of Bintropy as of https://ieeexplore.ieee.org/document/4140989.
    
    :param executable:                path to the executable to be analyzed
    :param full:                      process the executable as a whole or per section only (cfr modes of operation)
    :param blocksize:                 process per block of N bytes (0 means considering the executable as a whole)
    :param ignore_half_block_zeros:   ignore blocks having more than half of zeros
    :param decide:                    decide if packed or not, otherwise simply return the entropy values
    :param threshold_average_entropy: threshold on average entropy for deciding if packed
    :param threshold_highest_entropy: threshold on highest entropy for deciding if packed
    :param logger:                    logger instance for debug purpose
    :return:                          if decide is True  => bool (whether the input executable is packed or not)
                                                   False => (average_entropy, highest_block_entropy)
    """
    # try to parse the binary first ; capture the stderr messages from LIEF
    tmp_fd, null_fd = os.dup(2), os.open(os.devnull, os.O_RDWR)
    os.dup2(null_fd, 2)
    binary = lief.parse(str(executable))
    os.dup2(tmp_fd, 2)  # restore stderr
    os.close(null_fd)
    if binary is None:
        raise OSError("Unknown format")
    # now select the right thresholds
    thresholds = THRESHOLDS.get(binary.format, THRESHOLDS['default'])
    _t1, _t2 = threshold_average_entropy, threshold_highest_entropy
    _t1, _t2 = [_t1, thresholds[0]][_t1 is None], [_t2, thresholds[1]][_t2 is None]
    # FIRST MODE: compute the entropy of the whole executable
    if mode == 0:
        with open(str(executable), 'rb') as f:
            exe = f.read()
        __log(logger, "Entropy (Shannon): {}".format(entropy(exe)))
        e = entropy(exe, blocksize, ignore_half_block_zeros)
        if logger:
            msg = "Entropy (average): {}".format(e[1] or "-")
            if e[0] != [None]:
                iw = len(str(len(e[0])))
                for i, j in enumerate(e[0]):
                    msg += ("\n    #{: <%s}: {}" % iw).format(i + 1, "-" if j is None else j)
            __log(logger, msg)
        return is_packed(e[0], e[1], _t1, _t2, logger) if decide else (max([x for x in e[0] if x is not None]), e[1])
    # SECOND AND THIRD MODES: compute a weighted entropy of all the sections or segments of the executable
    else:
        def _handle(n, d):
            r = entropy(d, blocksize, ignore_half_block_zeros)
            e[n] = r if isinstance(r, (list, tuple)) else ([r], r)
            w[n] = len(d)
        e, w = {}, {}
        if mode == 1:  # per section
            if len(binary.sections) > 0:
                for section in binary.sections:
                    n, d = section.name, section.content
                    _handle(n, d)
            else:  # in some cases, packed executables can have no section ; e.g. UPX(/bin/ls)
                __log(logger, "This file has no section", "error")
                __log(logger, "please try another mode of operation", "warning")
                return
        elif mode == 2:  # per segment
            for i, segment in enumerate(binary.segments):
                _handle("segment #%d" % i, segment.content)
        else:
            raise NotImplementedError("This mode does not exist")
        if logger:
            msg = "Entropy per %s:" % ["section", "segment"][mode == 2]
            for name, entr in e.items():
                msg += "\n  %s: " % name
                msg += "-" if entr[1] is None else "%s (average)" % entr[1]
                if entr[0] != [None]:
                    for i, j in enumerate((entr or [[]])[0]):
                        msg += ("\n    #{: <%s}: {}" % len(str(len(entr[0])))).format(i + 1, "-" if j is None else j)
            __log(logger, msg)
        # aggregate per-section entropy scores with a simple weighted sum
        e2, e_avg2, t = 0, 0, 0
        for n, entr in e.items():
            if entr[1] in [.0, None]:
                continue
            e2 += max([x for x in entr[0] if x is not None]) * w[n]
            e_avg2 += entr[1] * w[n]
            t += w[n]
        e2, e_avg2 = e2 / t, e_avg2 / t
        return is_packed(e2, e_avg2, _t1, _t2, logger) if decide else (e2, e_avg2)


def entropy(something, blocksize=0, ignore_half_block_zeros=False):
    """ Shannon entropy, with the possibility to compute the entropy per block with a given size, possibly ignoring
         blocks in which at least half of the characters or bytes are zeros.
    
    :param something:               string or bytes
    :param blocksize:               block size to be considered for the total entropy
    :param ignore_half_block_zeros: ignore blocks in which at least half of the chars/bytes are zeros
    """
    e, l = [], len(something)
    if l == 0:
        return
    bs = blocksize or l
    n_blocks, n_ignored = math.ceil(float(l) / bs), 0
    for i in range(0, l, bs):
        block, n_zeros, ignore = something[i:i+bs], 0, False
        lb = len(block)
        # consider ignoring blocks in which more than half of the chars/bytes are zeros
        if ignore_half_block_zeros:
            lz = lb // 2
            for c in block:
                if isinstance(c, int) and c == 0 or isinstance(c, str) and ord(c) == 0:
                    n_zeros += 1
                if n_zeros > lz:
                    ignore = True
                    break
        # when ignore has been set to True, this means that the current block has more than half of its bytes filled
        #  with zeros ; then put None instead of an entropy value and increase the related counter
        if ignore:
            e.append(None)
            n_ignored += 1
            continue
        # if not ignored, process it
        d = {}
        for c in block:
            d.setdefault(c, 0)
            d[c] += 1
        e.append(-sum([p * math.log2(p) for p in [float(ctr) / lb for ctr in d.values()]]) or .0)
    # return the entropies per block and the average entropy of all blocks if n_blocks > 1
    return (e, sum([n or 0 for n in e]) / ((n_blocks - n_ignored) or 1)) if n_blocks > 1 else e[0]


def is_packed(entropies, average, threshold_average_entropy, threshold_highest_entropy, logger=None):
    """ Decision criteria as of https://ieeexplore.ieee.org/document/4140989.
    
    :param entropies:                 the list of block entropy values or the highest block entropy value
    :param average:                   the average block entropy
    :param threshold_average_entropy: threshold on average entropy for deciding if packed
    :param threshold_highest_entropy: threshold on highest entropy for deciding if packed
    :param logger:                    logger instance for debug purpose
    :return:                          whether the binary contains compressed/encrypted bytes given the thresholds
    """
    _t1, _t2 = threshold_average_entropy, threshold_highest_entropy
    if not isinstance(entropies, (list, tuple)):
        entropies = [entropies]
    entropies = [x for x in entropies if x is not None]
    if len(entropies) == 0:
        __log(logger, "No valid block found")
        return False
    max_e = max(entropies)
    c1 = average >= _t1
    c2 = max_e >= _t2
    __log(logger, "Average entropy criterion (>{}): {} ({})".format(_t1, c1, average))
    __log(logger, "Highest entropy criterion (>{}): {} ({})".format(_t2, c2, max_e))
    return c1 and c2


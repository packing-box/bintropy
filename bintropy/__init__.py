# -*- coding: UTF-8 -*-
import lief
import math
import matplotlib.pyplot as plt
import os
import statistics


__all__ = ["bintropy", "characteristics", "entropy", "is_packed", "plot", "THRESHOLDS"]


__log = lambda l, m, lvl="debug": getattr(l, lvl)(m) if l else None
__secname = lambda s: s.strip("\x00") or s or"<empty>"

# https://matplotlib.org/2.0.2/examples/color/named_colors.html
COLORS = {
    None:       ["salmon", "gold", "plum", "darkkhaki", "orchid", "sandybrown", "purple", "khaki", "peru", "thistle"],
    'headers':  "black",
    'overlay':  "lightgray",
    '<undef>':  "lightgray",
    # common
    'text':     "darkseagreen",   # code
    'data':     "skyblue",        # initialized data
    'bss':      "steelblue",      # block started by symbol (uninitialized data)
    # PE
    'rdata':    "cornflowerblue", # read-only data
    'rsrc':     "royalblue",      # resources
    'tls':      "slateblue",      # thread-local storage
    'edata':    "turquoise",      # export data
    'idata':    "darkturquoise",  # import data
    'reloc':    "crimson",        # base relocations table
    # ELF
    'init':     "lightgreen",     # runtime initialization instructions
    'fini':     "yellowgreen",    # process termination code
    'data1':    "skyblue",        # initialized data (2)
    'rodata':   "cornflowerblue", # read-only data
    'rodata1':  "cornflowerblue", # read-only data (2)
    'symtab':   "royalblue",      # symbol table
    'strtab':   "navy",           # string table
    'strtab1':  "navy",           # string table (2)
    'dynamic':  "crimson",        # dynamic linking information
    # Mach-O
    'cstring':  "navy",           # string table
    'const':    "cornflowerblue", # read-only data
    'literal4': "blue",           # 4-byte literal values
    'literal4': "mediumblue",     # 8-byte literal values
    'common':   "royalblue",      # uninitialized imported symbol definitions
}
MIN_ZONE_WIDTH = 5  # minimum number of samples on the entropy plot for a section (so that it can still be visible even
                    #  if it is far smaller than the other sections)
N_SAMPLES = 2048
SUBLABELS = {
    'ep':          lambda d: "EP at 0x%.8x in %s" % d['entrypoint'][1:],
    'size':        lambda d: "Size = %s" % _human_readable_size(d['size'], 1),
    'size-ep':     lambda d: "Size = %s\nEP at 0x%.8x in %s" % \
                             (_human_readable_size(d['size'], 1), d['entrypoint'][1], d['entrypoint'][2]),
    'size-ep-ent': lambda d: "Size = %s\nEP at 0x%.8x in %s\nAverage entropy: %.2f\nOverall entropy: %.2f" % \
                             (_human_readable_size(d['size'], 1), d['entrypoint'][1], d['entrypoint'][2],
                              statistics.mean(d['entropy']) * 8, d['entropy*']),
}
# IMPORTANT NOTE: these values were computed while experimenting with PE files and with the first mode of operation ;
#                  this may have an impact on typical values for other executable formats
THRESHOLDS = {
    'default':           (6.677, 7.199),  # average entropy, highest entropy
    lief.EXE_FORMATS.PE: (6.677, 7.199),
    #TODO: get average and highest entropy values for lief.EXE_FORMATS.ELF
    #TODO: get average and highest entropy values for lief.EXE_FORMATS.MACHO
}

plt.rcParams['font.family'] = "serif"


def _human_readable_size(size, precision=0):
    """ Convert size in bytes to a more readable form. """
    i, units = 0, ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    while size > 1024 and i < len(units):
        i += 1
        size /= 1024.0
    return "%.*f%s" % (precision, size, units[i])


def bintropy(executable, mode=0, blocksize=256, ignore_half_block_zeros=True, decide=True,
             threshold_average_entropy=None, threshold_highest_entropy=None, logger=None, **kwargs):
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


def characteristics(executable, n_samples=N_SAMPLES, window_size=lambda s: 2*s, **kwargs):
    """ Compute executable's desired characteristics, including:
        - 'x' samples of entropy using a sliding window of size 'window_size'
        - sections' bounds (reduced according to the 'x' samples)
        - executable type
        - entry point (set according to the 'x' samples)
    
    :param executable:  path to executable whose characteristics are to be computed
    :param n_samples:   number of samples of entropy required
    :param window_size: window size for computing the entropy
    """
    data = {'name': os.path.basename(executable), 'entropy': [], 'sections': []}
    # compute window-based entropy
    with open(str(executable), "rb") as f:
        data['entropy*'] = entropy(f.read())
    with open(str(executable), "rb") as f:
        size = data['size'] = os.fstat(f.fileno()).st_size
        step = abs(size // n_samples)
        chunksize = data['chunksize'] = size / n_samples
        if isinstance(window_size, type(lambda: 0)):
            window_size = window_size(step)
        # ensure the window interval is at least 256 (that is 2^8 ; with a 'security' factor of 2)) because otherwise if
        #  using a too small executable, it may get undersampled and have lower entropy values than actual
        window, winter = b"", max(step, abs(window_size // 2), 256)
        # rectify the size of the window with the fixed interval
        window_size = 2 * winter
        for i in range(n_samples+1):
            # slice the window
            new_pos, cur_pos = int((i+1)*chunksize), int(i*chunksize)
            window += f.read(new_pos - cur_pos if i > 0 else winter)
            window = window[max(0, len(window)-window_size) if cur_pos + winter < size else step:]
            # compute entropy
            data['entropy'].append(entropy(window)/8.)
    # compute other characteristics using LIEF (catch warnings from stderr)
    tmp_fd, null_fd = os.dup(2), os.open(os.devnull, os.O_RDWR)
    os.dup2(null_fd, 2)
    binary = lief.parse(str(executable))
    os.dup2(tmp_fd, 2)  # restore stderr
    os.close(null_fd)
    if binary is None:
        raise TypeError("Not an executable")
    data['type'] = "ELF" if type(binary) is lief.ELF.Binary else \
                   "Mach-O" if type(binary) is lief.MachO.Binary else \
                   "PE" if type(binary) is lief.PE.Binary else None
    if data['type'] is None:
        raise TypeError("Unsupported executable format")
    # entry point (EP)
    ep = binary.rva_to_offset(binary.optional_header.addressof_entrypoint)
    # sections
    __d = lambda s, e, n: (s, e, n, statistics.mean(data['entropy'][s:e+1]))
    data['sections'] = [__d(0, int(max(MIN_ZONE_WIDTH, binary.sizeof_headers // chunksize)), "Headers")]
    data['entrypoint'] = int(ep // data['chunksize'])
    ep_section = binary.section_from_rva(binary.optional_header.addressof_entrypoint).name.rstrip("\x00")
    # convert to 3-tuple (real EP, EP, section of real EP)
    data['entrypoint'] = (data['entrypoint'], ep, __secname(ep_section))
    for section in sorted(binary.sections, key=lambda x: x.offset):
        name = __secname(section.name)
        start = max(data['sections'][-1][1] if len(data['sections']) > 0 else 0, int(section.offset // chunksize))
        max_end = min(max(start + MIN_ZONE_WIDTH, int((section.offset + section.size) // chunksize)),
                      len(data['entropy']) - 1)
        data['sections'].append(__d(int(min(start, max_end - MIN_ZONE_WIDTH)), int(max_end), name))
    # fill in undefined sections
    prev_end = None
    for i, t in enumerate(data['sections'][:]):
        start, end, name, _ = t
        if prev_end and prev_end < start:
            data['sections'].insert(i, __d(prev_end, start, "<undef>"))
        prev_end = end
    # add overlay
    last = data['sections'][-1][1]
    if last + 1 < n_samples:
        data['sections'].append(__d(int(last), int(n_samples), "Overlay"))
    return data


def entropy(something, blocksize=0, ignore_half_block_zeros=False):
    """ Shannon entropy, with the possibility to compute the entropy per block with a given size, possibly ignoring
         blocks in which at least half of the characters or bytes are zeros.
    
    :param something:               string or bytes
    :param blocksize:               block size to be considered for the total entropy
    :param ignore_half_block_zeros: ignore blocks in which at least half of the chars/bytes are zeros
    """
    e, l = [], len(something)
    if l == 0:
        return 0.
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


def plot(*filenames, img_name=None, img_format="png", dpi=200, labels=None, sublabel=None, scale=False, **kwargs):
    """ Plot input binaries' characteristics on a same figure.
    
    :param img:        destination filename for the created figure
    :param filenames:  list of paths of the binaries to be included in the figure
    :param img_format: format of the created figure
    :param dpi:        resolution of the created figure
    :param labels:     list of custom labels to be used for the binaries (can be lambda-based)
    :param sublabel:   static or lambda-based sublabel for display under the label
    :param kwargs:     keyword-arguments for characteristics(...) ; n_samples and window_size
    """
    if len(filenames) == 0:
        raise ValueError("No executable to plot")
    nf, N_TOP, N_TOP2, N_BOT, N_BOT2 = len(filenames), 1.15, 1.37, -.15, -.37
    fig, objs = plt.subplots(nf+1, sharex=True)
    fig.set_size_inches(10, nf+1)
    fig.tight_layout(pad=1.5)
    objs[0].axis("off")
    ref_size, ref_n = None, kwargs.get('n_samples', N_SAMPLES)
    for i, filepath in enumerate(filenames):
        if scale and ref_size:
            with open(filepath, "rb") as f:
                size = os.fstat(f.fileno()).st_size
            kwargs['n_samples'] = int(ref_n * size / ref_size)
        data, obj, filename = characteristics(filepath, **kwargs), objs[i+1], os.path.basename(filepath)
        n, label = len(data['entropy']), None
        if not ref_size:
            ref_size = data['size']
        obj.axis("off")
        # set the main title for the whole figure
        if i == 0:
            fig.suptitle("Entropy per section of %s file: %s" % (data['type'], filename), x=[.6, .5][labels is None],
                         y=1.-.6/(nf+1), ha="center", va="bottom", fontsize="xx-large", fontweight="bold")
        # set the label and sublabel and display them
        try:
            label = labels[i]
            if isinstance(label, type(lambda: 0)):
                label = label(data)
        except:
            pass
        ref_point = .65
        if sublabel:
            if isinstance(sublabel, str):
                sublabel = SUBLABELS.get(sublabel)
            sl = sublabel(data) if isinstance(sublabel, type(lambda: 0)) else None
            if sl:
                nl, y_pos, f_color = len(sl.split("\n")), ref_point, "black"
                if label:
                    f_size, f_color = "x-small" if nl <= 2 else "xx-small", "gray"
                    y_pos = max(0., ref_point - nl * [.16, .12, .09, .08][min(4, nl)-1])
                else:
                    #y_pos -= nl * [0., .16, .3][min(3, nl)-1]
                    f_size = ["medium", "small", "x-small"][min(3, nl)-1]
                obj.text(s=sl, x=-420., y=y_pos, fontsize=f_size, color=f_color, ha="left", va="center")
        if label:
            y_pos = ref_point
            if sublabel:
                nl = len(sl.split("\n"))
                y_pos = min(1., ref_point + nl * [.16, .12, .09, .08][min(4, nl)-1])
            obj.text(s=label, x=-420., y=y_pos, fontsize="large", ha="left", va="center")
        # display the entry point
        obj.vlines(x=data['entrypoint'][0], ymin=0, ymax=1, color="r", zorder=11).set_label("Entry point")
        obj.text(data['entrypoint'][0], -.15, "______", c="r", ha="center", rotation=90, size=.8,
                 bbox={'boxstyle': "rarrow", 'fc': "r", 'ec': "r", 'lw': 1})
        color_cursor, last = 0, None
        for start, end, name, avg_ent in data['sections']:
            x = range(start, min(n, end + 1))
            # select the right color first
            try:
                c = COLORS[name.lower().lstrip("._").strip("\x00\n ")]
            except KeyError:
                co = COLORS[None]
                c = co[color_cursor % len(co)]
                color_cursor += 1
            # draw the section
            obj.fill_between(x, 0, 1, facecolor=c, alpha=.2)
            if name not in ["Headers", "Overlay"]:
                if last is None or (start + end) // 2 - (last[0] + last[1]) // 2 > n // 12:
                    pos_y = N_TOP
                else:
                    pos_y = N_BOT if pos_y in [N_TOP, N_TOP2] else N_TOP
                if last and last[2] and (start + end) // 2 - (last[2] + last[3]) // 2 < n // 15:
                    if pos_y == N_TOP:
                        pos_y = N_TOP2
                    elif pos_y == N_BOT:
                        pos_y = N_BOT2
                obj.text(s=name, x=start + (end - start) // 2, y=pos_y, zorder=12, color=c, ha="center", va="center")
                last = (start, end, last[0] if last else None, last[1] if last else None)
            # draw entropy
            obj.plot(x, data['entropy'][start:end+1], c=c, zorder=10, lw=.1)
            obj.fill_between(x, [0] * len(x), data['entropy'][start:end+1], facecolor=c)
            l = obj.hlines(y=statistics.mean(data['entropy'][start:end+1]), xmin=x[0], xmax=x[-1], color="black",
                           linestyle=(0, (5, 5)), linewidth=.5)
        l.set_label("Average entropy of section")
    plt.subplots_adjust(left=[.32, .02][labels is None], right=1.02, bottom=.5/max(1.75, nf))
    h, l = objs[1].get_legend_handles_labels()
    plt.figlegend(h, l, loc="lower center", ncol=2)
    img_name = img_name or os.path.splitext(os.path.basename(filenames[0]))[0]
    # appending the extension to img_name is necessary for avoiding an error when the filename contains a ".[...]" ;
    #  e.g. "PortableWinCDEmu-4.0" => this fails with "ValueError: Format '0' is not supported"
    plt.savefig(img_name + "." + img_format, img_format=img_format, dpi=dpi, bbox_inches="tight")
    return plt


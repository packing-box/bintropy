#!/usr/bin/python
# -*- coding: UTF-8 -*-
import logging
import os
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO
from random import Random
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

os.environ.setdefault("MPLBACKEND", "Agg")

import lief
from bintropy import *
from bintropy import _real_section_names, _section_name, SUBLABELS
from bintropy.__main__ import main


HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = {fmt: os.path.join(HERE, f"hello.{fmt}") for fmt in ["elf", "exe", "macho"]}
ELF, PE, MACHO = SAMPLES['elf'], SAMPLES['exe'], SAMPLES['macho']
LOGGER = logging.getLogger("test-bintropy")
LOGGER.setLevel(logging.DEBUG)


def make_packed(folder):
    """ Make a "packed" ELF by replacing the content of all its sections with (seeded) random bytes. """
    binary = lief.parse(ELF)
    start = min(s.offset for s in binary.sections if s.offset > 0 and s.size > 0)
    end = binary.header.section_header_offset
    with open(ELF, "rb") as f:
        data = bytearray(f.read())
    data[start:end] = Random(0).randbytes(end - start)
    path = os.path.join(folder, "packed.elf")
    with open(path, "wb") as f:
        f.write(data)
    return path


def run_cli(*args):
    """ Run the console script's main function, returning its exit code and standard output. """
    out = StringIO()
    with patch.object(sys, "argv", ["bintropy", *args]), redirect_stdout(out):
        code = main()
    return code, out.getvalue().strip()


class TestEntropy(TestCase):
    def test_whole_data(self):
        self.assertEqual(entropy(b""), 0.)
        self.assertEqual(entropy(b"aaaa"), 0.)
        self.assertEqual(entropy(b"abcd"), 2.)
        self.assertEqual(entropy("abcd"), 2.)
        self.assertEqual(entropy(bytes(range(256))), 8.)

    def test_blocks(self):
        self.assertEqual(entropy(b"", 256), ([], None))
        self.assertEqual(entropy(b"abcd" * 100, 256), ([2., 2.], 2.))
        self.assertEqual(entropy(b"ab", 256), ([1.], 1.))

    def test_ignored_blocks(self):
        data = b"\x00" * 256 + b"abcd" * 64
        # zero blocks are kept by default, and ignored on demand (for both bytes and strings)
        self.assertEqual(entropy(data, 256), ([0., 2.], 1.))
        self.assertEqual(entropy(data, 256, True), ([None, 2.], 2.))
        self.assertEqual(entropy(data.decode(), 256, True), ([None, 2.], 2.))
        # half a block is not more than half of it
        self.assertEqual(entropy(b"\x00" * 128 + b"ab" * 64, 256, True)[0], [1.5])
        # same-byte blocks are only ignored on demand
        data = b"\xff" * 256 + b"abcd" * 64
        self.assertEqual(entropy(data, 256, True), ([0., 2.], 1.))
        self.assertEqual(entropy(data, 256, False, True), ([None, 2.], 2.))
        # all the blocks ignored
        self.assertEqual(entropy(b"\x00" * 512, 256, True), ([None, None], 0.))


class TestIsPacked(TestCase):
    def test_criteria(self):
        self.assertTrue(is_packed([7., 7.5], 7., 6.677, 7.199))
        self.assertTrue(is_packed(7.199, 6.677, 6.677, 7.199, LOGGER))  # thresholds are inclusive
        self.assertFalse(is_packed([7., 7.5], 6., 6.677, 7.199))
        self.assertFalse(is_packed([7., 7.1], 7., 6.677, 7.199))
        self.assertTrue(is_packed([None, 7.5], 7.5, 6.677, 7.199))

    def test_no_valid_block(self):
        self.assertFalse(is_packed([], 0., 6.677, 7.199))
        self.assertFalse(is_packed([None, None], 0., 6.677, 7.199, LOGGER))


class TestBintropy(TestCase):
    def test_samples(self):
        for path in SAMPLES.values():
            for mode in [0, 1, 2]:
                for logger in [None, LOGGER]:
                    r = bintropy(path, mode=mode, logger=logger)
                    if path == PE and mode == 2 or path == MACHO and mode == 1:
                        self.assertIsNone(r)  # PE files have no segment and this Mach-O file has no section
                        continue
                    self.assertFalse(r)
                    highest, average = bintropy(path, mode=mode, decide=False, logger=logger)
                    self.assertGreaterEqual(highest, average)

    def test_modes(self):
        # mode 1 takes the highest block entropy of all the sections, not a weighted average of them
        highest = bintropy(ELF, mode=1, decide=False)[0]
        binary = lief.parse(ELF)  # keep a reference, as LIEF frees the sections with their binary
        sections = [entropy(s.content.tobytes(), 256, True) for s in binary.sections]
        self.assertEqual(highest, max(x for blocks, _ in sections for x in blocks if x is not None))
        # all the segments of this Mach-O file have their blocks ignored
        self.assertEqual(bintropy(MACHO, mode=2, decide=False), (0., 0.))
        self.assertFalse(bintropy(MACHO, mode=2))

    def test_options(self):
        # blocksize 0 considers the data as a whole
        highest, average = bintropy(ELF, blocksize=0, decide=False)
        self.assertEqual(highest, average)
        binary = lief.parse(ELF)  # keep a reference, as LIEF frees the sections with their binary
        self.assertEqual(bintropy(ELF, mode=1, blocksize=0, decide=False)[0],
                         max(entropy(s.content.tobytes()) for s in binary.sections))
        self.assertTrue(bintropy(ELF, threshold_average_entropy=0, threshold_highest_entropy=0))
        self.assertNotEqual(bintropy(ELF, decide=False), bintropy(ELF, ignore_half_block_zeros=False, decide=False))
        self.assertEqual(bintropy(ELF, parsed=lief.parse(ELF), decide=False), bintropy(ELF, decide=False))
        self.assertIsNotNone(bintropy(ELF, ignore_half_block_same_byte=True, decide=False))
        # all the blocks ignored
        self.assertEqual(bintropy(MACHO, decide=False), (0., 0.))

    def test_packed(self):
        with TemporaryDirectory() as tmp:
            path = make_packed(tmp)
            for mode in [0, 2]:
                self.assertTrue(bintropy(path, mode=mode))
            # in mode 1, the many small sections of this sample (smaller than a block) keep the average entropy low
            highest, average = bintropy(path, mode=1, decide=False)
            self.assertGreater(highest, 7.199)
            self.assertGreater(average, bintropy(ELF, mode=1, decide=False)[1])

    def test_errors(self):
        self.assertRaises(OSError, bintropy, __file__)
        self.assertRaises(NotImplementedError, bintropy, ELF, mode=3)


class TestCharacteristics(TestCase):
    def test_samples(self):
        for fmt, path in SAMPLES.items():
            data = characteristics(path, n_samples=256)
            self.assertEqual(data['type'], {'elf': "ELF", 'exe': "PE", 'macho': "MachO"}[fmt])
            self.assertEqual(len(data['entropy']), 257)
            self.assertTrue(all(0. <= e <= 1. for e in data['entropy']))
            self.assertEqual(data['size'], os.path.getsize(path))
        self.assertEqual(characteristics(ELF, parsed=lief.parse(ELF), n_samples=256)['sections'],
                         characteristics(ELF, n_samples=256)['sections'])
        self.assertIsNone(characteristics(MACHO, n_samples=256)['entrypoint'])
        self.assertRaises(TypeError, characteristics, __file__)

    @patch.dict(os.environ, {'PATH': ""})
    def test_section_names_without_objdump(self):
        _real_section_names.cache_clear()
        try:
            names = [s[2] for s in characteristics(PE, n_samples=256, logger=LOGGER)['sections']]
        finally:
            _real_section_names.cache_clear()
        self.assertIn("/4", names)

    def test_section_names_with_objdump(self):
        if subprocess.run(["which", "objdump"], capture_output=True).returncode != 0:
            self.skipTest("objdump is not installed")
        names = [s[2] for s in characteristics(PE, n_samples=256)['sections']]
        self.assertIn(".debug_info", names)
        self.assertNotIn("/4", names)
        self.assertEqual(_section_name(PE, ".text", 0), ".text")
        self.assertEqual(_section_name(PE, "/4", 1000), "/4")
        self.assertIsNone(_real_section_names(__file__, logger=LOGGER))

    def test_objdump_timeout(self):
        _real_section_names.cache_clear()
        with patch("subprocess.Popen") as popen:
            popen.return_value.communicate.side_effect = [subprocess.TimeoutExpired("objdump", 10), (b"", b"")]
            self.assertIsNone(_real_section_names(PE, logger=LOGGER))
            popen.return_value.kill.assert_called_once()
        _real_section_names.cache_clear()

    def test_no_fd_leak(self):
        if not os.path.isdir("/proc/self/fd"):
            self.skipTest("/proc/self/fd is not available")
        n = len(os.listdir("/proc/self/fd"))
        for _ in range(5):
            characteristics(ELF, n_samples=64)
        self.assertRaises(TypeError, characteristics, __file__)
        self.assertEqual(len(os.listdir("/proc/self/fd")), n)


class TestPlot(TestCase):
    def setUp(self):
        self._cwd, self._tmp = os.getcwd(), TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_default_name(self):
        plot(ELF, n_samples=256)
        self.assertTrue(os.path.isfile("hello.png"))

    def test_options(self):
        plot(ELF, PE, MACHO, img_name="all", img_format="jpg", dpi=50, labels=["ELF", lambda d: d['type']],
             sublabel="size-ep-ent", scale=True, target="samples", n_samples=256)
        self.assertTrue(os.path.isfile("all.jpg"))
        for sublabel in SUBLABELS:
            plot(ELF, img_name=sublabel, sublabel=sublabel, n_samples=256)
            self.assertTrue(os.path.isfile(f"{sublabel}.png"))
        plot(PE, img_name="side", sublabel=lambda d: "custom", legend_location="center right", no_title=True,
             parsed=lief.parse(PE), n_samples=256)
        self.assertTrue(os.path.isfile("side.png"))
        self.assertIsNotNone(plot(ELF, img_name="plt", return_plt=True, n_samples=256))

    def test_no_entry_point(self):
        # sublabels referring to the entry point are skipped when there is none, also after the first file
        plot(MACHO, img_name="macho", labels=["Mach-O"], sublabel="ep", n_samples=256)
        plot(ELF, MACHO, img_name="both", labels=["ELF", "Mach-O"], sublabel="size-ep", n_samples=256)
        self.assertTrue(os.path.isfile("macho.png"))
        self.assertTrue(os.path.isfile("both.png"))

    def test_errors(self):
        self.assertRaises(ValueError, plot)


class TestCLI(TestCase):
    def test_outputs(self):
        self.assertEqual(run_cli(ELF), (0, "False"))
        code, out = run_cli(ELF, "--do-not-decide", "-m", "1", "-b")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.split()), 3)
        self.assertEqual(run_cli(ELF, "--blocksize", "0", "--all-blocks", "-v")[0], 0)
        self.assertEqual(run_cli(ELF, "--threshold-average-entropy", "0", "--threshold-highest-entropy", "0.0"),
                         (0, "True"))
        self.assertEqual(run_cli(ELF, "--ignore-half-block-same-byte", "-m", "2"), (0, "False"))

    def test_errors(self):
        self.assertEqual(run_cli(__file__), (1, ""))
        self.assertEqual(run_cli(PE, "-m", "2"), (1, ""))
        for args in [["--blocksize", "1+"], ["--blocksize", "-1"], ["--blocksize", "1.5"], ["-m", "3"]]:
            with self.assertRaises(SystemExit) as cm:
                run_cli(ELF, *args)
            self.assertEqual(cm.exception.code, 2)
        for path in ["does-not-exist", HERE]:
            with self.assertRaises(SystemExit):
                run_cli(path)

    def test_plot(self):
        cwd = os.getcwd()
        with TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                self.assertEqual(run_cli(ELF, "-p"), (0, "False"))
                self.assertTrue(os.path.isfile("hello.png"))
                with patch("bintropy.__main__.plot", side_effect=RuntimeError("test")):
                    self.assertEqual(run_cli(ELF, "-p", "-v"), (1, "False"))
            finally:
                os.chdir(cwd)

    def test_module(self):
        env = {**os.environ, 'PYTHONPATH': os.path.join(os.path.dirname(HERE), "src")}
        p = subprocess.run([sys.executable, "-m", "bintropy", ELF], capture_output=True, env=env)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, b"False"))

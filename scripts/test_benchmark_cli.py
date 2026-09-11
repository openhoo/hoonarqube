#!/usr/bin/env python3
"""Focused Linux regressions for the manual CLI benchmark harness."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import benchmark_cli  # noqa: E402


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "waitid") and hasattr(os, "WNOWAIT"),
    "benchmark lifecycle tests require Linux waitid",
)
class BenchmarkCliLifecycleTests(unittest.TestCase):
    """Keep wedged children and malformed output from invalidating the host."""

    _CHILD_CODE = textwrap.dedent(
        """
        import os
        import pathlib
        import signal
        import sys
        import time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding="ascii")
        while True:
            time.sleep(60)
        """
    )

    @staticmethod
    def _wait_for_file(
        path: Path, process: subprocess.Popen[str], timeout: float = 2.0
    ):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists() and path.read_text(encoding="ascii").strip():
                return
            if process.poll() is not None:
                raise AssertionError(f"helper exited {process.returncode}")
            time.sleep(0.01)
        raise AssertionError(f"timed out waiting for {path}")

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        except (FileNotFoundError, ProcessLookupError):
            return False
        except PermissionError:
            return True
        _, _, tail = state.rpartition(") ")
        return not tail.startswith("Z ")

    def _launch_wedged_group(self, root: Path):
        pid_file = root / "descendant.pid"
        parent_code = textwrap.dedent(
            f"""
            import pathlib
            import subprocess
            import sys
            child = subprocess.Popen([sys.executable, '-c', {self._CHILD_CODE!r}, sys.argv[1]])
            child.wait()
            """
        )
        stdout = (root / "stdout").open("wb")
        stderr = (root / "stderr").open("wb")
        process = subprocess.Popen(
            [sys.executable, "-c", parent_code, str(pid_file)],
            cwd=ROOT,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            self._wait_for_file(pid_file, process)
            return process, int(pid_file.read_text(encoding="ascii")), stdout, stderr
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            stdout.close()
            stderr.close()
            raise

    def test_timeout_kills_term_ignoring_descendant_group(self):
        with tempfile.TemporaryDirectory(prefix="benchmark-timeout-test-") as name:
            root = Path(name)
            process, descendant, stdout, stderr = self._launch_wedged_group(root)
            try:
                status, _, timed_out = benchmark_cli._reap(process, 0.05)
                self.assertTrue(timed_out)
                self.assertEqual(process.returncode, os.waitstatus_to_exitcode(status))
                self.assertLess(process.returncode, 0)
                deadline = time.monotonic() + 2.0
                while self._alive(descendant) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(self._alive(descendant))
            finally:
                stdout.close()
                stderr.close()
                if self._alive(descendant):
                    os.kill(descendant, signal.SIGKILL)
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()

    def test_sigint_reaps_group_before_propagating(self):
        with tempfile.TemporaryDirectory(prefix="benchmark-interrupt-test-") as name:
            root = Path(name)
            pid_file = root / "descendant.pid"
            ready_file = root / "waitid.ready"
            runner_code = textwrap.dedent(
                f"""
                import pathlib
                import subprocess
                import sys
                sys.path.insert(0, {str(ROOT / "scripts")!r})
                import benchmark_cli
                child_code = {self._CHILD_CODE!r}
                child = subprocess.Popen(
                    [sys.executable, '-c', child_code, sys.argv[1]], start_new_session=True
                )
                original_waitid = benchmark_cli._waitid
                def observed_waitid(pid):
                    pathlib.Path(sys.argv[2]).write_text('ready', encoding='ascii')
                    return original_waitid(pid)
                benchmark_cli._waitid = observed_waitid
                benchmark_cli._reap(child, 30.0)
                """
            )
            runner = subprocess.Popen(
                [sys.executable, "-c", runner_code, str(pid_file), str(ready_file)],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                self._wait_for_file(pid_file, runner)
                self._wait_for_file(ready_file, runner)
                descendant = int(pid_file.read_text(encoding="ascii"))
                os.kill(runner.pid, signal.SIGINT)
                runner.wait(timeout=5.0)
                self.assertNotEqual(runner.returncode, 0)
                deadline = time.monotonic() + 2.0
                while self._alive(descendant) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(self._alive(descendant))
            finally:
                if runner.poll() is None:
                    os.killpg(runner.pid, signal.SIGKILL)
                    runner.wait()
                if pid_file.exists():
                    descendant = int(pid_file.read_text(encoding="ascii"))
                    if self._alive(descendant):
                        os.kill(descendant, signal.SIGKILL)

    def test_child_rss_is_independent_of_parent_heap(self):
        command = [
            sys.executable,
            "-c",
            "import sys; payload = b'x' * (32 * 1024 * 1024); sys.stdout.write('{}\\n')",
        ]
        cpus = sorted(os.sched_getaffinity(0))[:1]
        with tempfile.TemporaryDirectory(prefix="benchmark-rss-test-") as name:
            root = Path(name)
            before = benchmark_cli.measure(
                command,
                ROOT,
                cpus,
                root / "before",
                "json",
                5.0,
            )
            payload = bytearray(128 * 1024 * 1024)
            for offset in range(0, len(payload), 4096):
                payload[offset] = 1
            after = benchmark_cli.measure(
                command,
                ROOT,
                cpus,
                root / "after",
                "json",
                5.0,
            )
        self.assertTrue(before["successful"])
        self.assertTrue(after["successful"])
        self.assertIsNotNone(before["peak_rss_kib"])
        self.assertIsNotNone(after["peak_rss_kib"])
        self.assertLess(
            after["peak_rss_kib"],
            before["peak_rss_kib"] + 64 * 1024,
        )

    def test_decoder_recursion_failure_is_recorded_as_invalid_output(self):
        with tempfile.TemporaryDirectory(prefix="benchmark-json-test-") as name:
            output = Path(name) / "output.json"
            output.write_text("[" * 3000 + "0" + "]" * 3000, encoding="utf-8")
            with patch.object(
                benchmark_cli.json,
                "load",
                side_effect=RecursionError("decoder recursion limit"),
            ):
                valid, error = benchmark_cli._validate_output(output, "json")
        self.assertFalse(valid)
        self.assertTrue(error)


if __name__ == "__main__":
    unittest.main()

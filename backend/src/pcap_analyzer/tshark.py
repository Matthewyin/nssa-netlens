import shutil
import subprocess
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional


class TsharkManager:
    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = tshark_path or self._find_tshark()

    def set_path(self, path: str):
        if path and os.path.exists(path):
            self.tshark_path = path

    def _find_tshark(self) -> Optional[str]:
        # 1. Check environment variable
        if os.environ.get("TSHARK_PATH"):
            return os.environ["TSHARK_PATH"]

        # 2. Check bundled binary (relative to this script)
        # Assuming structure: resources/bin/tshark inside the app bundle
        # Adjust '..' count based on actual packing
        bundled_path = (
            Path(__file__).parent.parent.parent.parent / "resources" / "bin" / "tshark"
        )
        if bundled_path.exists() and os.access(bundled_path, os.X_OK):
            return str(bundled_path)

        # 3. Check standard macOS Wireshark path
        macos_app_path = "/Applications/Wireshark.app/Contents/MacOS/tshark"
        if os.path.exists(macos_app_path):
            return macos_app_path

        # 4. Check PATH
        return shutil.which("tshark")

    def is_available(self) -> bool:
        return self.tshark_path is not None and os.path.exists(self.tshark_path)

    def get_version(self) -> str:
        if not self.is_available():
            return "Not found"
        try:
            # Safe cast
            cmd = [str(self.tshark_path), "-v"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.splitlines()[0]
        except Exception as e:
            return f"Error: {str(e)}"

    def run_json(
        self,
        pcap_path: str,
        display_filter: Optional[str] = None,
        fields: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Run tshark and return JSON output.
        WARNING: Can consume lots of memory for large files. Use filters!
        """
        if not self.is_available():
            raise RuntimeError("Tshark not found")

        # Cast to str to satisfy type checker, though is_available guarantees not None
        tshark_exe = str(self.tshark_path)

        cmd = [tshark_exe, "-r", pcap_path, "-T", "json"]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        if fields:
            for field in fields:
                cmd.extend(["-e", field])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Tshark failed: {e.stderr}")
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse Tshark JSON output")

    def stream_fields(
        self, pcap_path: str, fields: list[str], display_filter: Optional[str] = None
    ):
        """
        Generator yielding dicts of fields for each packet.
        Uses -T fields -E separator=, -E header=y -E quote=d
        """
        if not self.is_available():
            raise RuntimeError("Tshark not found")

        cmd = [
            str(self.tshark_path),
            "-r",
            pcap_path,
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-E",
            "header=y",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]

        for f in fields:
            cmd.extend(["-e", f])

        if display_filter:
            cmd.extend(["-Y", display_filter])

        import csv

        # Use Popen to stream stdout
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
        try:
            if proc.stdout:
                reader = csv.DictReader(proc.stdout)
                for row in reader:
                    yield row
        finally:
            proc.kill()
            proc.wait()


# Global instance
tshark = TsharkManager()

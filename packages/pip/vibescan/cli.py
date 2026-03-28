"""
vibescan CLI wrapper — downloads and runs the vibescan Go binary.

On first run, downloads the correct binary for your OS/arch from GitHub Releases.
Subsequent runs use the cached binary.
"""

import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import json
import zipfile

REPO = "Armur-Ai/vibescan"
BIN_DIR = os.path.join(os.path.expanduser("~"), ".vibescan", "bin")
RELEASES_URL = f"https://api.github.com/repos/{REPO}/releases/latest"


def _platform_info():
    """Return (os_name, arch) matching goreleaser naming."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"darwin": "darwin", "linux": "linux", "windows": "windows"}
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }

    os_name = os_map.get(system)
    arch = arch_map.get(machine)

    if not os_name or not arch:
        print(f"Unsupported platform: {system}/{machine}", file=sys.stderr)
        sys.exit(1)

    return os_name, arch


def _get_latest_version():
    """Fetch the latest release tag from GitHub."""
    try:
        req = urllib.request.Request(
            RELEASES_URL, headers={"User-Agent": "vibescan-pip-installer"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("tag_name", "v0.0.1")
    except Exception:
        return "v0.0.1"


def _bin_path():
    """Return the path to the vibescan binary."""
    name = "vibescan.exe" if platform.system().lower() == "windows" else "vibescan"
    return os.path.join(BIN_DIR, name)


def _download_binary():
    """Download and install the vibescan binary."""
    os_name, arch = _platform_info()
    version = _get_latest_version()
    tag = version.lstrip("v")

    ext = "zip" if os_name == "windows" else "tar.gz"
    filename = f"vibescan_{tag}_{os_name}_{arch}.{ext}"
    url = f"https://github.com/{REPO}/releases/download/{version}/{filename}"

    os.makedirs(BIN_DIR, exist_ok=True)

    print(f"Downloading vibescan {version} for {os_name}/{arch}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_file = os.path.join(tmpdir, filename)
        urllib.request.urlretrieve(url, tmp_file)

        bin_name = "vibescan.exe" if os_name == "windows" else "vibescan"
        dest = os.path.join(BIN_DIR, bin_name)

        if ext == "tar.gz":
            with tarfile.open(tmp_file, "r:gz") as tar:
                tar.extract(bin_name, path=BIN_DIR)
        else:
            with zipfile.ZipFile(tmp_file, "r") as z:
                z.extract(bin_name, path=BIN_DIR)

        if os_name != "windows":
            os.chmod(dest, os.stat(dest).st_mode | stat.S_IEXEC)

    print(f"vibescan {version} installed to {dest}")


def main():
    """Entry point — download binary if needed, then exec it."""
    binary = _bin_path()

    if not os.path.isfile(binary):
        _download_binary()

    if not os.path.isfile(binary):
        print("Failed to install vibescan binary.", file=sys.stderr)
        print("Install manually: brew install Armur-Ai/tap/vibescan", file=sys.stderr)
        sys.exit(1)

    try:
        result = subprocess.run([binary] + sys.argv[1:])
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"Failed to run vibescan: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

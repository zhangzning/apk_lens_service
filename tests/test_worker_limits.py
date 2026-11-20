import subprocess
import sys


def test_worker_limits_are_inherited_without_raising_existing_limits(tmp_path):
    check_limits = """
import errno
import os
import resource
import subprocess
import sys
from apk_lens_service.config import MIB, ParseToolSettings
from apk_lens_service.worker_limits import apply_process_limits

resource.setrlimit(resource.RLIMIT_CPU, (6, 9))
config = ParseToolSettings(
    cpu_seconds=12, max_file_mib=1,
    address_space_mib=8192 if sys.platform == "linux" else 0,
)
apply_process_limits(config)
assert resource.getrlimit(resource.RLIMIT_CPU) == (6, 9)
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (MIB, MIB)
if config.address_space_mib:
    assert resource.getrlimit(resource.RLIMIT_AS) == (8192 * MIB, 8192 * MIB)
path = sys.argv[1]
with open(path, "wb", buffering=0) as output:
    output.write(b"a" * MIB)
    try:
        output.write(b"a")
    except OSError as exc:
        assert exc.errno == errno.EFBIG
    else:
        raise AssertionError("worker exceeded its file size limit")
assert os.stat(path).st_size == MIB

child = (
    "import resource; "
    "assert resource.getrlimit(resource.RLIMIT_FSIZE) == (1048576, 1048576); "
    "assert resource.getrlimit(resource.RLIMIT_CPU) == (6, 9)"
)
subprocess.run([sys.executable, "-c", child], check=True)
"""
    subprocess.run(
        [sys.executable, "-c", check_limits, str(tmp_path / "bounded.bin")],
        check=True, timeout=10,
    )

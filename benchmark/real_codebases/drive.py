import os
import sys
from pathlib import Path
from leakmap import runner
runner.ADDON = Path(sys.argv[1])
out, cwd = Path(sys.argv[2]), sys.argv[3]
os.chdir(cwd)
code, _ = runner.run(sys.argv[4:], out, stub=True)
print("exit", code)

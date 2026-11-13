#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Set up kalkan on Linux and macOS (Git Bash on Windows also works).
# The script does these steps in the repository root:
#   1. Find Python 3.11 or later (python3, python).
#   2. Create .venv when it is missing.
#   3. Install kalkan into .venv: pip install -e . Then check that kalkan imports (on macOS:
#      that the .pth file of the install is not hidden).
#   4. Install every pinned tool, the Go toolchain included: kalkan tools install --all
#   5. Download the local vulnerability databases: kalkan sca update-db --max-age 168 (a
#      database younger than 7 days, the stale limit of kalkan doctor, is kept; a failure only
#      warns: sca match then records a database gap; it never queries an online API)
#   6. Check the environment: kalkan doctor
# Steps 1 to 3 stop the script at the first failure. Step 6 also runs after a failed step 4,
# so that the doctor table shows what is missing. The exit code is 1 when step 4 failed or
# when the doctor reports a fail (a manifest tool missing or broken). Docker and git are
# warnings only.
#
# Usage: sh scripts/bootstrap.sh

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname -- "$script_dir")
version_check='import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'

say() {
    printf '==> %s\n' "$*"
}

fail() {
    printf 'bootstrap: error: %s\n' "$*" >&2
    exit 1
}

find_python() {
    for candidate in python3 python python3.14 python3.13 python3.12 python3.11; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c "$version_check" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

venv_python() {
    if [ -x "$repo_root/.venv/bin/python" ]; then
        printf '%s\n' "$repo_root/.venv/bin/python"
    elif [ -f "$repo_root/.venv/Scripts/python.exe" ]; then
        printf '%s\n' "$repo_root/.venv/Scripts/python.exe"
    else
        return 1
    fi
}

if py=$(venv_python); then
    say "Use the existing .venv ($py)"
else
    base=$(find_python) ||
        fail "Python 3.11 or later was not found. Install it and run this script again."
    say "Create .venv with $base"
    "$base" -m venv "$repo_root/.venv" ||
        fail "python -m venv failed. On Debian or Ubuntu, install the python3-venv package."
    py=$(venv_python) || fail "python -m venv did not create a Python interpreter in .venv."
fi

"$py" -c "$version_check" ||
    fail ".venv does not run Python 3.11 or later. Remove .venv and run this script again."

say "Install kalkan into .venv (pip install -e .)"
"$py" -m pip install --disable-pip-version-check --no-cache-dir -e "$repo_root" ||
    fail "pip install -e . failed."

# The editable install points .venv at src/ with a .pth file. Python 3.13 and later skip a
# .pth file that macOS marks hidden, and kalkan then cannot be imported ("No module named
# kalkan.__main__"). On one Mac (macOS 26.7.1, 2026-11-13) every file of a .venv below
# ~/Desktop was hidden, and the flag came back at once after chflags nohidden.
hidden_pth='import glob, os, stat, sys, sysconfig
site = sysconfig.get_paths()["purelib"]
files = glob.glob(os.path.join(site, "*kalkan*.pth"))
sys.exit(1 if any(getattr(os.stat(f), "st_flags", 0) & stat.UF_HIDDEN for f in files) else 0)'
if [ "$(uname -s)" = Darwin ] && ! "$py" -c "$hidden_pth"; then
    chflags -R nohidden "$repo_root/.venv" 2>/dev/null || true
    "$py" -c "$hidden_pth" ||
        fail "macOS keeps the files of .venv hidden in this folder, and Python skips a hidden .pth file, so kalkan cannot be imported. This was seen below ~/Desktop (a folder that iCloud can sync). Clone the repository into another folder, for example ~/kalkan, and run this script there."
fi
"$py" -c 'import kalkan.cli' ||
    fail "kalkan cannot be imported from .venv after pip install -e . Remove .venv and run this script again."

say "Install every pinned tool, Go included (kalkan tools install --all)"
install_code=0
"$py" -m kalkan tools install --all || install_code=$?

say "Download the local vulnerability databases (kalkan sca update-db --max-age 168)"
"$py" -m kalkan sca update-db --max-age 168 ||
    printf 'bootstrap: warning: %s\n' "kalkan sca update-db failed; sca match records a database gap until it works. Run: $py -m kalkan sca update-db" >&2

say "Check the environment (kalkan doctor)"
doctor_code=0
"$py" -m kalkan doctor || doctor_code=$?

if [ "$install_code" -ne 0 ]; then
    fail "kalkan tools install --all failed with exit code $install_code. Read the table above, fix the cause and run this script again."
fi
if [ "$doctor_code" -ne 0 ]; then
    fail "kalkan doctor reported a fail (exit code $doctor_code). Run the command in the DETAIL column of each fail row, then run this script again."
fi

case "$py" in
    */Scripts/python.exe) say "Done. Activate the venv with: . .venv/Scripts/activate" ;;
    *) say "Done. Activate the venv with: . .venv/bin/activate" ;;
esac

#!/bin/bash

set -euo pipefail
scriptdir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

# activate venv
cd "$(dirname "${scriptdir}")"
if [ -z "${VIRTUAL_ENV:-}" ]; then
  if [ ! -d .venv ]; then
    python3 -m venv .venv
  fi
  source .venv/bin/activate
fi

# install deps
python3 -m pip --require-virtualenv -qqq install -r requirements.txt

cd "${scriptdir}"
# run test files
for file in *.repl; do
  echo -e "\033[94m[TEST]\033[0m Running \033[2m$file\033[0m"
  if python3 ../src/restreplay/rere.py "$file"; then
    echo -e " + \033[92mPassed!\033[0m"
  else
    echo -e " + \033[91mFAILED!\033[0m"
    exit 1
  fi
done

#!/usr/bin/env bash
# Run real codebases through leakmap (--stub: nothing reaches real services), then
# capture the same traffic raw and compare. Needs uv and network access to PyPI/GitHub.
#   benchmark/real_codebases/run.sh [work-dir]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:-/tmp/leakmap-real}; mkdir -p "$W/logs"
LEAKMAP="$HERE/../../.venv/bin/leakmap"; PY="$HERE/../../.venv/bin/python"
export LLM_USER_PATH=$W/llm-home; mkdir -p "$LLM_USER_PATH"

cd "$W"
[ -d llm-anthropic ] || git clone -q --depth 1 https://github.com/simonw/llm-anthropic
(cd llm-anthropic && uv sync -q)
for lib in crewai chromadb litellm gradio; do
  [ -x "$W/venv-$lib/bin/python" ] || uv venv -q --python 3.12 "$W/venv-$lib"
  uv pip install -q --python "$W/venv-$lib/bin/python" "$lib"
  uv pip freeze --python "$W/venv-$lib/bin/python" > "$W/logs/$lib-freeze.txt"
  uvx --quiet pip-audit@2.10.1 -r "$W/logs/$lib-freeze.txt" --no-deps --disable-pip --progress-spinner off > "$W/logs/$lib-audit.log" 2>&1
done

cmd_llm=(.venv/bin/python -m pytest -q -p no:cacheprovider --disable-recording)
(cd llm-anthropic && "$LEAKMAP" run --stub --out "$W/out-llm-anthropic" -- "${cmd_llm[@]}" > "$W/logs/llm-anthropic.log" 2>&1)
"$PY" "$HERE/drive.py" "$HERE/rawcap.py" "$W/gt/llm-anthropic" "$W/llm-anthropic" "${cmd_llm[@]}" > /dev/null 2>&1
for lib in crewai chromadb litellm gradio; do
  "$LEAKMAP" run --stub --out "$W/out-$lib" -- "$W/venv-$lib/bin/python" "$HERE/apps/${lib}_app.py" > "$W/logs/$lib.log" 2>&1
  "$PY" "$HERE/drive.py" "$HERE/rawcap.py" "$W/gt/$lib" "$W" "$W/venv-$lib/bin/python" "$HERE/apps/${lib}_app.py" > /dev/null 2>&1
done
"$PY" "$HERE/compare.py" "$W/gt" llm-anthropic crewai litellm gradio

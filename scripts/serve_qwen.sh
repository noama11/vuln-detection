#!/bin/bash
# serve_qwen.sh - bring up the local Qwen3-32B-AWQ vLLM OpenAI-compatible server
# on the CURRENT node (this session already holds a SLURM job with an RTX 4090).
#
#   bash scripts/serve_qwen.sh          # start (or reuse) the server, wait for health
#   bash scripts/serve_qwen.sh --stop   # shut it down
#   bash scripts/serve_qwen.sh --small  # fallback sizing if the default OOMs
#
# Writes .vllm/{pid,endpoint,server.log} (gitignored). Idempotent: if a healthy
# server is already answering on $PORT it exits immediately.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$ROOT/.vllm"
LOG="$STATE/server.log"
PIDF="$STATE/pid"
ENDF="$STATE/endpoint"

PY=/home/noama1/envs/vllm_serve/bin/python
MODEL_PATH=/home/noama1/models/qwen3-32b
SERVED_NAME=qwen3-32b-awq
HOST=127.0.0.1
PORT=${VLLM_PORT:-8000}

# Default sizing: 18GB of AWQ weights on a 24GB card leaves ~4.3GB for KV.
# fp8 KV is ~128KB/token -> ~34k tokens of cache, so a 16k context window fits
# with room for several concurrent sequences. 16k covers p99.9 of our prompts.
MAX_LEN=16384
GPU_UTIL=0.93
MAX_SEQS=8

mkdir -p "$STATE"

health() { curl -sf --max-time 3 "http://$HOST:$PORT/health" >/dev/null 2>&1; }

if [ "${1:-}" = "--stop" ]; then
  if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
    kill "$(cat "$PIDF")" && echo "stopped vllm (pid $(cat "$PIDF"))"
    rm -f "$PIDF" "$ENDF"
  else
    echo "no running server recorded"
  fi
  exit 0
fi

if [ "${1:-}" = "--small" ]; then
  MAX_LEN=8192
  GPU_UTIL=0.95
  MAX_SEQS=4
  echo "using fallback sizing: max-model-len=$MAX_LEN gpu-util=$GPU_UTIL"
fi

if health; then
  echo "vllm already healthy at http://$HOST:$PORT/v1"
  echo "http://$HOST:$PORT/v1" > "$ENDF"
  exit 0
fi

echo "node:  $(hostname)"
nvidia-smi --query-gpu=index,name,memory.total,memory.used --format=csv,noheader
echo "model: $MODEL_PATH"
echo "log:   $LOG"

# setsid puts the server in its own session/process group. Without it the
# server is killed the moment whatever shell launched it has its process group
# cleaned up - which is exactly what happens when an agent/CI tool reaps the
# command it ran. The server must outlive its launcher.
PYTHONNOUSERSITE=1 HF_HOME=/home/noama1/hf_cache \
setsid nohup "$PY" -m vllm.entrypoints.openai.api_server \
  --model "$MODEL_PATH" \
  --served-model-name "$SERVED_NAME" \
  --quantization awq_marlin \
  --dtype float16 \
  --max-model-len "$MAX_LEN" \
  --gpu-memory-utilization "$GPU_UTIL" \
  --kv-cache-dtype fp8 \
  --max-num-seqs "$MAX_SEQS" \
  --host "$HOST" --port "$PORT" \
  < /dev/null > "$LOG" 2>&1 &

echo $! > "$PIDF"
disown 2>/dev/null || true
echo "launched pid $(cat "$PIDF"), waiting for health (18GB of weights to load)..."

# ~10 min ceiling: AWQ weight load off NFS is the slow part.
for i in $(seq 1 200); do
  if health; then
    echo "http://$HOST:$PORT/v1" > "$ENDF"
    echo
    echo "READY -> http://$HOST:$PORT/v1  (model: $SERVED_NAME)"
    nvidia-smi --query-gpu=memory.used --format=csv,noheader
    exit 0
  fi
  if ! kill -0 "$(cat "$PIDF")" 2>/dev/null; then
    echo "server process died. last 40 log lines:"
    tail -40 "$LOG"
    exit 1
  fi
  sleep 3
done

echo "timed out waiting for health. last 40 log lines:"
tail -40 "$LOG"
exit 1

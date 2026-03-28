#!/bin/sh
set -e

echo "Starting zkDB Plonky3..."

# Start Rust backend on port 3001
zkdb serve --bind 0.0.0.0:3001 &
BACKEND_PID=$!
echo "Backend started (PID $BACKEND_PID) on :3001"

# Start Next.js standalone on port 3000
cd /app/frontend
node server.js &
FRONTEND_PID=$!
echo "Frontend started (PID $FRONTEND_PID) on :3000"

# If either process dies, kill the other and exit
wait -n 2>/dev/null || true
echo "A process exited. Shutting down..."
kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
wait

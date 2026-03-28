#!/bin/bash
set -e

echo "Starting zkDB Plonky3..."

# Start Rust backend on port 3001
zkdb serve --bind 0.0.0.0:3001 &
BACKEND_PID=$!
echo "Backend started (PID $BACKEND_PID) on :3001"

# Start Next.js standalone on port 3000 (bind to all interfaces for Coolify)
cd /app/frontend
HOSTNAME=0.0.0.0 PORT=3000 node server.js &
FRONTEND_PID=$!
echo "Frontend started (PID $FRONTEND_PID) on :3000"

# Trap signals and kill both on exit
trap "echo 'Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" TERM INT

# Wait for either process to exit (bash 4.3+ feature)
wait -n $BACKEND_PID $FRONTEND_PID
echo "A process exited unexpectedly. Shutting down..."
kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
wait

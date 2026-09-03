#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/rust"
cargo build --release -p ignite-server
IGNITE_CONFIG_DIR=.. ./target/release/ignite-server

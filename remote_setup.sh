#!/bin/bash
# Remote machine setup script for alt1 proof generation
# Run this on the remote machine with sufficient RAM (64+ GB recommended)

set -e

WORK_DIR="${HOME}/bitvm-alt1"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "=== Setting up Alt1 Proof Generator ==="
echo "Working directory: $WORK_DIR"

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Clone the stwo-circle-poseidon-plonk prover (with SHA256 fixes)
if [ ! -d "stwo-circle-poseidon-plonk" ]; then
    echo "Cloning stwo-circle-poseidon-plonk (alt1-sha256-fixes branch)..."
    git clone -b alt1-sha256-fixes https://github.com/Bitcoin-Wildlife-Sanctuary/stwo-circle-poseidon-plonk.git
fi

# Clone the recursive-stwo-bitcoin repo
if [ ! -d "recursive-stwo-bitcoin" ]; then
    echo "Cloning recursive-stwo-bitcoin (alternative-1-pure-sha256 branch)..."
    git clone -b alternative-1-pure-sha256 https://github.com/Bitcoin-Wildlife-Sanctuary/recursive-stwo-bitcoin.git
fi

cd recursive-stwo-bitcoin

# Update the Cargo.toml patch to point to local stwo-prover
echo "Updating Cargo.toml patch path..."
if ! grep -q "patch.*stwo-circle-poseidon-plonk" Cargo.toml; then
    cat >> Cargo.toml << 'EOF'

[patch.'https://github.com/Bitcoin-Wildlife-Sanctuary/stwo-circle-poseidon-plonk/']
stwo-prover = { path = "../stwo-circle-poseidon-plonk/crates/prover" }
EOF
fi

# Create data directory
mkdir -p data

# Get the level13-1.bin proof file (needed as input)
LEVEL13_PATH="$HOME/.cargo/git/checkouts/recursive-stwo-9c7bf9c393de374c/caea77f/examples/multi-proofs/data/level13-1.bin"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To generate the alt1 proof:"
echo "  1. Copy level13-1.bin to the expected location:"
echo "     mkdir -p ~/.cargo/git/checkouts/recursive-stwo-9c7bf9c393de374c/caea77f/examples/multi-proofs/data/"
echo "     # (You'll need to copy level13-1.bin from your local machine)"
echo ""
echo "  2. Run validation first:"
echo "     cd $WORK_DIR/recursive-stwo-bitcoin"
echo "     cargo run --release -p alt1-proof-generator"
echo ""
echo "  3. Generate the actual proof (requires 64+ GB RAM):"
echo "     GENERATE_PROOF=1 cargo run --release -p alt1-proof-generator"
echo ""
echo "Output will be saved to: data/alt1_real_proof.bin"

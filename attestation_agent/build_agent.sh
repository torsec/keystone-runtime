#!/bin/bash

set -e

# Adjust the paths as necessary
KEYSTONE_SRC_DIR="../"

# If the compiler is not installed, install it with the following command:
# sudo apt install -y g++-riscv64-linux-gnu

riscv64-linux-gnu-g++ -static attestation_agent.cpp -o attestation_agent
if [ $? -ne 0 ]; then
    echo "Compilation failed. Please check the code for errors."
    exit 1
fi

echo "Attestation agent compiled successfully."

# Create the temp directory if it doesn't exist
mkdir -p ./build
mv attestation_agent ./build/

# Copy the compiled agent to the Keystone build directory
# NOTE: Keystone must be already built
cp ./build/attestation_agent "$KEYSTONE_SRC_DIR"/build-generic64/overlay/root/

# Now build again Keystone
cd $KEYSTONE_SRC_DIR
make -j$(nproc)

echo "Attestation agent built and moved to the Keystone build directory."


# Note: to run the agent, you can connect using SSH once the Keystone QEMU VM has started:
#       ssh -p 9821 root@localhost
# You can then run the agent with:
#       ./attestation_agent
# Attestation Agent
Attestation agent used to support run-time attestation in the Keystone Enclave framework.

## Dependencies

To install the RISC-V (64-bit) cross-compiler, run:

```sh
sudo apt install -y g++-riscv64-linux-gnu
```

## How to build
Simply, run the *build_agent.sh* script. It will automatically build the Agent and then move it to the Keystone build directory.

## How to test the attestation framework

### 1. Run the Verifier
*verifier.py* provides a simple verifier to test the attestation functionalities. To run it, open a terminal and just execute:
```sh
python3 verifier.py
```

### 2. Run a (test) enclave application
To launch an enclave application to be attested (i.e., *hello.ke*), first open the terminal in a new session and launch the Keystone QEMU VM. Once logged in, insert the keystone-driver kernel module with:
```sh
modprobe keystone-driver
```

Finally, launch the enclave application with
```sh
/usr/share/keystone/examples/hello.ke
```

### 3. Run the Agent
To run the agent, spawn another terminal. In here, you can connect using SSH once the Keystone QEMU VM has started:

```sh
ssh -p 9821 root@localhost
```

You can then execute it with:

```sh
./attestation_agent
```

Now, it should connect with the Verifier and start attesting the enclave application
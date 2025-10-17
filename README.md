# cuPQC OpenSSL Provider Integration

## Overview

This repository contains a fork of OpenSSL that integrates a new, in-tree provider module named `cupqcprov`. This provider enables GPU-accelerated post-quantum cryptography (PQC) by integrating **NVIDIA's cuPQC library** directly into the OpenSSL framework.

The primary goal of this project is to implement the **ML-KEM-768** Key Encapsulation Mechanism (KEM) as a pluggable and selectable algorithm in OpenSSL 3.x. This allows applications to leverage GPU hardware for performance-critical PQC operations seamlessly through OpenSSL's standard APIs.

---

## Key Features

*   **In-Tree Provider Module (`cupqcprov`)**: The functionality is implemented as a self-contained provider, which is the modern, modular way to extend OpenSSL.
*   **GPU Acceleration for PQC**: Implements ML-KEM-768 operations by calling the highly optimized cuPQC library, offloading cryptographic work to compatible NVIDIA GPUs.
*   **Dynamic Loading**: The provider finds and loads the `libcupqc.so` shared library at runtime using `dlopen` and `dlsym`. This makes cuPQC an **optional dependency**, ensuring this OpenSSL build remains portable and can run on systems without a GPU or the cuPQC SDK.
*   **Property-Based Selection**: The GPU-accelerated algorithm is tagged with the custom property `accelerated=gpu`. This allows applications to explicitly request the GPU implementation, coexisting cleanly with the standard CPU version from OpenSSL's default provider.

***

## What This Repository Contains

This repository includes all the necessary source code and build system modifications to integrate the `cupqcprov` provider.

*   **`providers/cupqcprov/`**: A new directory containing all the source code for the provider.
    *   `cupqcprov.c`: The main entry point that registers the provider and its algorithms with OpenSSL.
    *   `cupqc_wrap.h` / `cupqc_wrap.c`: A wrapper that handles the dynamic loading of the `libcupqc.so` library and checks for its availability.
    *   `kem_mlkem_cupqc.c`: The implementation of the KEM interface for ML-KEM-768.
    *   `keymgmt_mlkem_cupqc.c`: The implementation of the key management interface (key generation, import, export) for ML-KEM-768.
    *   `build.info`: Build instructions that define how to compile the provider module.

*   **Build System Modifications**:
    *   `providers/build.info`: Modified to conditionally include the `cupqcprov` subdirectory in the build.
    - `Configure`: Patched to add a new `--enable-cupqc` feature flag.

***

## Next Steps

This repository is currently under development. Instructions for building, installing, and testing the provider will be added once the implementation is finalized and validated on a GPU-based environment.

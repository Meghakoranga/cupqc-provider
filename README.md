# cuPQC OpenSSL Provider

GPU-accelerated post-quantum cryptography provider for OpenSSL 3.x using NVIDIA cuPQC.

## Features
- ML-KEM-768 Key Encapsulation Mechanism with GPU acceleration
- Standalone out-of-tree provider (no OpenSSL source modification)
- Drop-in replacement for CPU ML-KEM implementations

## Requirements
- OpenSSL 3.0 or later (with development headers)
- NVIDIA cuPQC SDK
- CUDA Toolkit 11.0+
- CMake 3.18+

## Building

```
mkdir build && cd build
cmake ..
make
sudo make install
```

## Usage

Create OpenSSL config file (e.g., `openssl-cupqc.cnf`):

```
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
cupqcprov = cupqcprov_sect

[default_sect]
activate = 1

[cupqcprov_sect]
module = /usr/local/lib64/ossl-modules/cupqcprov.so
activate = 1
```

Generate ML-KEM-768 keypair with GPU acceleration:

```

OPENSSL_CONF=openssl-cupqc.cnf openssl genpkey
-algorithm ML-KEM-768
-propquery 'accelerated=gpu'
-out key.pem
```

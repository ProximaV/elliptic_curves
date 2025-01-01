# Elliptic Curve Cryptography Module in Python

This Python module provides an implementation of Elliptic Curve Cryptography (ECC) over both prime fields (GF(p)) and binary fields (GF(2<sup>m</sup>)). It includes support for fundamental operations such as point addition, point doubling, scalar multiplication, ECDSA signature generation and verification, solving for \( y \) given \( x \) on the curve, and Pollard's Rho algorithm for the Elliptic Curve Discrete Logarithm Problem (ECDLP).

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Prime Field Elliptic Curves](#prime-field-elliptic-curves)
  - [Binary Field Elliptic Curves](#binary-field-elliptic-curves)
- [Classes and Methods](#classes-and-methods)
  - [`EllipticCurveBase`](#ellipticcurvebase)
  - [`PrimeFieldEllipticCurve`](#primefieldellipticcurve)
  - [`BinaryFieldEllipticCurve`](#binaryfieldellipticcurve)
- [Examples](#examples)
  - [ECDSA Signature Generation and Verification](#ecdsa-signature-generation-and-verification)
  - [Pollard's Rho Algorithm](#pollards-rho-algorithm)
- [Important Considerations](#important-considerations)
- [License](#license)

## Features

- **Elliptic Curve Operations**: Implementations of point addition, point doubling, and scalar multiplication.
- **Support for Prime and Binary Fields**: Classes for elliptic curves over GF(p) and GF(2<sup>m</sup>).
- **ECDSA Implementation**: Methods for ECDSA signature generation and verification.
- **Quadratic Equation Solving**: Functions to solve quadratic equations over GF(2<sup>m</sup>), including the use of the half-trace function for fields with odd \( m \).
- **Pollard's Rho Algorithm**: Implementation of Pollard's Rho algorithm for solving the Elliptic Curve Discrete Logarithm Problem.

## Installation

### Dependencies

- **Python 3.6 or higher**

This module relies on Python's built-in arbitrary-precision integers (`int` type), so no external libraries are required.

## Usage

### Prime Field Elliptic Curves

```python
from elliptic_curve import PrimeFieldEllipticCurve

# Define curve parameters for secp256k1
p = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16)
a = 0
b = 7
Gx = int('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16)
Gy = int('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16)
G = (Gx, Gy)
n = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)

# Create the curve
curve = PrimeFieldEllipticCurve(p=p, a=a, b=b, n=n, G=G)

# Verify that G is on the curve
print("G is on the curve:", curve.is_on_curve(G))

# Perform scalar multiplication
k = int('1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF', 16)
Q = curve.scalar_mult(k, G)
print("Q =", Q)
```

### Binary Field Elliptic Curves

```python
from elliptic_curve import BinaryFieldEllipticCurve

# Define field and curve parameters
m = 163
poly_coeffs = [163, 7, 6, 3, 0]  # Irreducible polynomial for GF(2^163)
a = 1
b = 1
Gx = 0x3f0eba16286a2d57ea0991168d4994637e8343e36
Gy = 0x0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1
G = (Gx, Gy)
n = 0x40000000000000000000292fe77e70c12a4234c33

# Create the curve
curve = BinaryFieldEllipticCurve(m=m, poly_coeffs=poly_coeffs, a=a, b=b, n=n, G=G)

# Verify that G is on the curve
print("G is on the curve:", curve.is_on_curve(G))

# Perform scalar multiplication
k = 0x1234567890ABCDEF1234567890ABCDEF12345678
Q = curve.scalar_mult(k, G)
print("Q =", Q)
```

## Classes and Methods

### `EllipticCurveBase`

An abstract base class that defines the common interface and methods for elliptic curves.

#### Methods

- `is_on_curve(P)`: Check if a point `P` lies on the curve.
- `point_add(P, Q)`: Add two points `P` and `Q`.
- `point_double(P)`: Double a point `P`.
- `scalar_mult(k, P)`: Multiply a point `P` by a scalar `k`.
- `pollards_rho(P, Q)`: Solve for `k` in `Q = k * P` using Pollard's Rho algorithm (for prime fields).

### `PrimeFieldEllipticCurve`

Implements elliptic curve operations over prime fields GF(p).

#### Constructor

```python
PrimeFieldEllipticCurve(p, a, b, n=None, G=None)
```

- `p`: The prime modulus.
- `a`, `b`: Curve coefficients.
- `n`: Order of the base point `G` (optional).
- `G`: Base point (optional).

#### Additional Methods

- `ecdsa_sign(message, d)`: Sign a message using the private key `d`.
- `ecdsa_verify(message, signature, Q)`: Verify a signature using the public key `Q`.
- `solve_y(x)`: Compute the possible `y` coordinates for a given `x`.
- `pollards_rho(P, Q)`: Solve for `k` in `Q = k * P` using Pollard's Rho algorithm.

### `BinaryFieldEllipticCurve`

Implements elliptic curve operations over binary fields GF(2<sup>m</sup>).

#### Constructor

```python
BinaryFieldEllipticCurve(m, poly_coeffs, a, b, n=None, G=None)
```

- `m`: Degree of the field.
- `poly_coeffs`: Exponents of the irreducible polynomial.
- `a`, `b`: Curve coefficients.
- `n`: Order of the base point `G` (optional).
- `G`: Base point (optional).

#### Additional Methods

- `solve_y(x)`: Compute the possible `y` coordinates for a given `x` using the half-trace function when `m` is odd.

## Examples

### ECDSA Signature Generation and Verification

#### Prime Field Curve (secp256k1)

```python
from elliptic_curve import PrimeFieldEllipticCurve
import hashlib
import os

# Curve parameters
p = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16)
a = 0
b = 7
Gx = int('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16)
Gy = int('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16)
G = (Gx, Gy)
n = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)

# Create the curve
curve = PrimeFieldEllipticCurve(p=p, a=a, b=b, n=n, G=G)

# Generate a private key d
d = int.from_bytes(os.urandom(32), byteorder='big') % n
if d == 0:
    d = 1

# Compute public key Q = d * G
Q = curve.scalar_mult(d, G)

# Message to sign
message = b"Hello, ECDSA!"

# Sign the message
signature = curve.ecdsa_sign(message, d)
print("Signature:")
print("r =", hex(signature[0]))
print("s =", hex(signature[1]))

# Verify the signature
is_valid = curve.ecdsa_verify(message, signature, Q)
print("Signature valid?", is_valid)
```

#### Output

```
Signature:
r = 0x...
s = 0x...
Signature valid? True
```

### Pollard's Rho Algorithm

#### Solving for the Discrete Logarithm

```python
from elliptic_curve import PrimeFieldEllipticCurve

# Curve parameters (small example for demonstration)
p = 9739
a = 497
b = 1768
G = (1804, 5368)
n = 9721  # Order of G

# Create the curve
curve = PrimeFieldEllipticCurve(p=p, a=a, b=b, n=n, G=G)

# Private key d (unknown)
d = 1829

# Compute public key Q = d * G
Q = curve.scalar_mult(d, G)

# Use Pollard's Rho algorithm to find d given G and Q
found_d = curve.pollards_rho(G, Q)
print(f"Found d: {found_d}")

# Verify
print(f"Private key matches: {d == found_d}")
```

#### Output

```
Found d: 1829
Private key matches: True
```

## Important Considerations

- **Cryptographic Security**: This module is intended for educational purposes. For production systems, use established cryptographic libraries that have been thoroughly tested and audited.
- **Randomness**: Ensure that random numbers (e.g., private keys, nonces) are generated securely using a cryptographically secure random number generator.
- **Side-Channel Attacks**: Implementations must be constant-time to prevent timing attacks. The provided code does not account for such security measures.
- **Field Arithmetic**: When working with large fields, optimize field arithmetic operations (`field_mul`, `field_inv`, etc.) for better performance.
- **Performance**: Python's built-in integers support arbitrary precision but may be slower than specialized libraries for large numbers.

## License

This project is licensed under the MIT License.

---

**Disclaimer**: The code provided is for educational purposes and may not be suitable for production use. Always consult security experts and use well-established libraries for cryptographic applications.
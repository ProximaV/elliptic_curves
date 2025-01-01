class EllipticCurveBase:
    def __init__(self, a, b, n):
        """Base class for elliptic curves."""
        self.a = a
        self.b = b
        self.n = n

    def find_next_point(self, x):
        for i in range (x,x+0x1000):
            y = self.solve_y(i)
            if len(y) > 0:
                newP= (i,y[0])
                if self.is_on_curve(newP) is True:
                    return newP
        return None

    def pollards_rho(self, P, Q, max_steps=10000000, num_subsets=64):
        """
        Solve for k in Q = kP using Pollard's Rho algorithm.
        Returns k if found, or None if not found within max_steps.
        """
        if self.n is None:
            raise ValueError("Curve order n must be specified for Pollard's Rho.")

        # Adjust for cofactor
        if hasattr(self, 'cofactor') and self.cofactor > 1:
            P = self.scalar_mult(self.cofactor, P)
            Q = self.scalar_mult(self.cofactor, Q)

        def partition(P, num_subsets):
            if P is None:
                return 0
            x = P[0]
            x_int = int(x)
            return x_int % num_subsets

        # Initialize variables
        X = P
        a = 1
        b = 0

        Y = P
        A = 1
        B = 0

        for i in range(1, max_steps + 1):
            X, a, b = self._pollards_rho_step(X, a, b, P, Q, partition, num_subsets)
            Y, A, B = self._pollards_rho_step(Y, A, B, P, Q, partition, num_subsets)
            Y, A, B = self._pollards_rho_step(Y, A, B, P, Q, partition, num_subsets)

            if X == Y:
                r = (a - A) % self.n
                s = (B - b) % self.n
                if s == 0:
                    # Retry with different parameters
                    return None
                try:
                    s_inv = pow(s, -1, self.n)
                    k = (r * s_inv) % self.n
                    # Verify the solution
                    if self.scalar_mult(k, P) == Q:
                        return k
                    else:
                        return None
                except ValueError:
                    return None
        return None

    def _pollards_rho_step(self, P, a, b, P0, Q, partition, num_subsets):
        if P is None:
            return P, a, b

        subset = partition(P, num_subsets)
        if subset < num_subsets // 3:
            # P = P + Q
            P_new = self.point_add(P, Q)
            a_new = a
            b_new = (b + 1) % self.n
        elif subset < 2 * num_subsets // 3:
            # P = 2P
            P_new = self.point_double(P)
            a_new = (2 * a) % self.n
            b_new = (2 * b) % self.n
        else:
            # P = P + P0
            P_new = self.point_add(P, P0)
            a_new = (a + 1) % self.n
            b_new = b
        return P_new, a_new, b_new

    # Common methods that can be shared or overridden by subclasses
    def is_on_curve(self, P):
        raise NotImplementedError("Must be implemented by subclass.")

    def point_add(self, P, Q):
        raise NotImplementedError("Must be implemented by subclass.")

    def point_double(self, P):
        raise NotImplementedError("Must be implemented by subclass.")

    def scalar_mult(self, k, P):
        """Multiply a point P by an integer k modulo n using the double-and-add algorithm."""
        if P is None:
            return None
        if self.n:
            k = k % self.n  # Reduce k modulo n
            if k == 0:
                return None  # Return point at infinity

        result = None  # Point at infinity
        addend = P

        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1

        return result

    def solve_y(self, x):
        raise NotImplementedError("Must be implemented by subclass.")

    def _hash_message(self,message):
        """Simulate a hash function by converting the message to an integer."""
        # Simple hash function for demonstration purposes
        return sum(ord(c) for c in message)

    def ecdsa_sign(self, message, d, k):
        """
        Generate an ECDSA signature.
        :param curve: The elliptic curve.
        :param message: The message as a string.
        :param d: The private key.
        :param k: A random nonce, should be unique and secret for each signature.
        :return: A tuple (r, s) representing the signature.
        """
        n = self.n
        e = self._hash_message(message) % n

        # Calculate r
        x1, y1 = self.scalar_mult(k, self.G)
        r = x1 % n
        if r == 0:
            raise ValueError("r cannot be zero")

        # Calculate s
        k_inv = inverse_mod(k, n)
        s = (k_inv * (e + d * r)) % n
        if s == 0:
            raise ValueError("s cannot be zero")

        return (r, s)

    def ecdsa_verify(self, message, signature, Q):
        """
        Verify an ECDSA signature.
        :param message: The message as a string.
        :param signature: A tuple (r, s).
        :param Q: The public key point on the curve.
        :return: True if the signature is valid, False otherwise.
        """
        r, s = signature
        n = self.n

        if not (1 <= r < n and 1 <= s < n):
            return False

        # Convert the message to an integer e
        e = self._hash_message(message) % n

        w = inverse_mod(s, n)
        u1 = (e * w) % n
        u2 = (r * w) % n

        # Calculate point (x1, y1) = u1 * G + u2 * Q
        point1 = self.scalar_mult(u1, self.G)
        point2 = self.scalar_mult(u2, Q)
        point = self.point_add(point1, point2)

        if point is None:
            return False

        x1, y1 = point
        return (r % n) == (x1 % n)

class BinaryFieldEllipticCurve(EllipticCurveBase):
    def __init__(self, m, poly_coeffs, a, b, n=None, G=None, h=None):
        super().__init__(a, b, n)
        self.m = m
        self.poly_coeffs = poly_coeffs  # Exponents of the irreducible polynomial
        self.n = n  # Order of the base point G
        self.G = G  # Base point
        if h:
            self.cofactor = h  # Cofactor
        else:
            self.cofactor = 2



    def get_irreducible_poly(self):
        """Constructs the irreducible polynomial from the exponents."""
        poly = 1 << self.m
        for k in self.poly_coeffs[1:]:
            poly ^= 1 << k
        return poly

    def _reduce(self, x):
        """Reduce a polynomial x modulo the irreducible polynomial."""
        modulus = self.get_irreducible_poly()
        while x.bit_length() > self.m:
            x ^= modulus << (x.bit_length() - self.m - 1)
        return x

    def field_add(self, x, y):
        """Addition in GF(2^m) is XOR."""
        return x ^ y

    def field_mul(self, x, y):
        """Multiplication in GF(2^m) with reduction modulo the irreducible polynomial."""
        result = 0
        while y:
            if y & 1:
                result ^= x
            y >>= 1
            x = self._reduce(x << 1)
        return self._reduce(result)

    def field_inv(self, x):
        """Multiplicative inverse in GF(2^m) using Extended Euclidean Algorithm."""
        modulus = self.get_irreducible_poly()
        u, v = x, modulus
        g1, g2 = 1, 0
        while u != 0:
            if u.bit_length() < v.bit_length():
                u, v = v, u
                g1, g2 = g2, g1
            j = u.bit_length() - v.bit_length()
            u ^= v << j
            g1 ^= g2 << j
            u = self._reduce(u)
            g1 = self._reduce(g1)
        if v != 1:
            raise ZeroDivisionError("No inverse exists for this element.")
        return self._reduce(g2)

    def field_div(self, x, y):
        """Division in GF(2^m): x / y."""
        y_inv = self.field_inv(y)
        return self.field_mul(x, y_inv)

    def field_sqrt(self, x):
        """Compute the square root of x in GF(2^m)."""
        result = x
        for _ in range(self.m - 1):
            result = self.field_mul(result, result)
        return result

    def is_on_curve(self, P):
        if P is None:
            return True  # Point at infinity
        x, y = P
        lhs = self.field_add(self.field_mul(y, y), self.field_mul(x, y))
        rhs = self.field_add(
            self.field_mul(x, self.field_mul(x, x)),
            self.field_add(self.field_mul(self.a, self.field_mul(x, x)), self.b),
        )
        return lhs == rhs

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if self.field_add(y1, y2) == 0:
                return None  # Point at infinity
            else:
                return self.point_double(P)

        # Compute lambda = (y1 + y2) / (x1 + x2)
        numerator = self.field_add(y1, y2)
        denominator = self.field_add(x1, x2)
        if denominator == 0:
            return None  # Vertical line, point at infinity
        lambda_ = self.field_div(numerator, denominator)

        # Compute x3 = lambda^2 + lambda + x1 + x2 + a
        x3 = self.field_add(
            self.field_add(
                self.field_mul(lambda_, lambda_), lambda_
            ), self.field_add(x1, x2)
        )
        x3 = self.field_add(x3, self.a)

        # Compute y3 = lambda * (x1 + x3) + x3 + y1
        y3 = self.field_add(
            self.field_mul(lambda_, self.field_add(x1, x3)), x3
        )
        y3 = self.field_add(y3, y1)

        return (self._reduce(x3), self._reduce(y3))

    def point_double(self, P):
        if P is None:
            return None

        x1, y1 = P

        if x1 == 0:
            return None  # Point at infinity

        # Compute lambda = x1 + y1 / x1
        lambda_ = self.field_add(x1, self.field_div(y1, x1))

        # Compute x3 = lambda^2 + lambda + a
        x3 = self.field_add(
            self.field_add(
                self.field_mul(lambda_, lambda_), lambda_
            ), self.a
        )

        # Compute y3 = x1^2 + (lambda + 1) * x3
        lambda_plus_1 = self.field_add(lambda_, 1)
        x1_squared = self.field_mul(x1, x1)
        y3 = self.field_add(
            x1_squared, self.field_mul(lambda_plus_1, x3)
        )

        return (self._reduce(x3), self._reduce(y3))

    def scalar_mult(self, k, P):
        if P is None:
            return None
        if self.n:
            k = k % self.n  # Reduce k modulo n
            if k == 0:
                return None  # Return point at infinity

        result = None  # Point at infinity
        addend = P

        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1

        return result

    def solve_quadratic_simple(self, c):
        """Solve y^2 + y = c in GF(2^m)."""
        # Compute the trace of c
        if self.trace(c) == 0:
            # Equation has two solutions
            y0 = self._sqrt(c)
            y1 = self.field_add(y0, 1)
            return [y0, y1]
        else:
            # No solution exists
            return []

    def solve_artin_schreier(self, beta):
        """
        Solve z^2 + z + beta = 0 in GF(2^m).
        Returns a list of solutions z.
        """
        if self.trace(beta) == 0:
            # There are two solutions: z and z + 1
            z = self._sqrt(beta)
            if z is not None:
                return [z, self.field_add(z, 1)]
            else:
                # Shouldn't happen as trace(beta) == 0 implies solutions exist
                return []
        else:
            # No solution exists
            return []

    def solve_quadratic(self, p, q):
        """
        Solve y^2 + p y + q = 0 in GF(2^m).
        Returns a list of solutions y.
        """
        if p == 0:
            # Equation simplifies to y^2 = q
            y = self._sqrt(q)
            if y is not None:
                return [y]
            else:
                return []
        else:
            # Compute beta = q / p^2
            p_inv = self.field_inv(p)
            p_inv_squared = self.field_mul(p_inv, p_inv)
            beta = self.field_mul(q, p_inv_squared)

            # Solve z^2 + z + beta = 0
            solutions_z = self.solve_artin_schreier(beta)

            # Compute y = p * z
            solutions_y = [self.field_mul(p, z) for z in solutions_z]
            return solutions_y

    def trace(self, x):
        """Compute the trace of x over GF(2), returns 0 or 1."""
        bit_count = bin(x).count('1')
        return bit_count % 2

    def _sqrt(self, x):
        """Compute the square root of x in GF(2^m)."""
        result = x
        for _ in range(self.m - 1):
            result = self.field_mul(result, result)
        return result

    def half_trace(self, a):
        """
        Compute the half-trace of 'a' in GF(2^m) when m is odd.
        Returns an element x such that x^2 + x = a.
        """
        result = a
        power = a
        for _ in range(1, (self.m + 1) // 2):
            # Compute power = power^{(2)^2} = power^{4}
            power = self.field_mul(power, power)  # Square
            power = self.field_mul(power, power)  # Square again
            result = self.field_add(result, power)
        return result

    def solve_y(self, x):
        """
        Solve for y given x on the elliptic curve over GF(2^m).
        The curve equation is y^2 + x y = x^3 + a x^2 + b
        """
        x = x % (1 << self.m)  # Ensure x is within GF(2^m)

        # Compute c = x^3 + a x^2 + b
        x2 = self.field_mul(x, x)  # x^2
        x3 = self.field_mul(x, x2)  # x^3
        ax2 = self.field_mul(self.a, x2)  # a x^2
        c = self.field_add(x3, self.field_add(ax2, self.b))

        if x == 0:
            # When x = 0, the equation simplifies to y^2 = c
            # So y = sqrt(c)
            y = self._sqrt(c)
            if y is not None:
                return [y]
            else:
                return []
        else:
            # For m odd, use the half-trace function
            if self.m % 2 == 1:
                x_inv = self.field_inv(x)
                x_inv_squared = self.field_mul(x_inv, x_inv)
                a = self.field_mul(c, x_inv_squared)
                z = self.half_trace(a)
                y = self.field_mul(x, z)
                return [y]
            else:
                # For m even, fall back to the previous method
                return self.solve_quadratic(x, c)



class PrimeFieldEllipticCurve(EllipticCurveBase):
    def __init__(self, p, a, b, n=None, G=None):
        """Elliptic curve over a prime field GF(p)."""
        super().__init__(a, b, n)
        self.p = p
        self.G = G  # Base point in affine coordinates
        # Ensure the curve is non-singular: 4a^3 + 27b^2 ≠ 0 mod p
        if (4 * a**3 + 27 * b**2) % p == 0:
            raise ValueError("The curve is singular!")

    def is_on_curve(self, P):
        if P is None:
            return True  # Point at infinity
        x, y = P
        lhs = (y * y) % self.p
        rhs = (x**3 + self.a * x + self.b) % self.p
        return lhs == rhs

    def point_add(self, P, Q):
        """Add two points P and Q on the elliptic curve over GF(p) using affine coordinates."""
        if P is None:
            return Q
        if Q is None:
            return P

        p = self.p
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if (y1 + y2) % p == 0:
                return None  # Point at infinity
            else:
                return self.point_double(P)

        # Calculate the slope (lambda)
        inv = inverse_mod((x2 - x1) % p, p)
        lam = ((y2 - y1) * inv) % p

        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p

        return (x3, y3)

    def point_double(self, P):
        """Double a point P on the elliptic curve over GF(p) using affine coordinates."""
        if P is None:
            return None

        p = self.p
        x1, y1 = P

        if y1 == 0:
            return None  # Point at infinity

        # Calculate the slope (lambda)
        inv = inverse_mod((2 * y1) % p, p)
        lam = ((3 * x1 * x1 + self.a) * inv) % p

        x3 = (lam * lam - 2 * x1) % p
        y3 = (lam * (x1 - x3) - y1) % p

        return (x3, y3)

    def solve_y(self, x):
        """Solve for y given x on the elliptic curve over GF(p)."""
        rhs = (x**3 + self.a * x + self.b) % self.p
        y = modular_sqrt(rhs, self.p)
        if y is None:
            return []  # No solutions
        else:
            return [y, (-y) % self.p]  # Both square roots

# Helper functions
def inverse_mod(k, p):
    """Compute the modular inverse of k modulo p."""
    k = k % p
    if k == 0:
        raise ZeroDivisionError("Inverse does not exist")
    # Extended Euclidean Algorithm
    s, old_s = 0, 1
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, (old_r - quotient * r)
        old_s, s = s, (old_s - quotient * s)
    if old_r != 1:
        raise ValueError(f"No inverse exists for {k} modulo {p}")
    return old_s % p

def modular_sqrt(a, p):
    """Compute the square root of a modulo p (p must be prime)."""
    # For p ≡ 3 mod 4
    if p % 4 == 3:
        sqrt = pow(a, (p + 1) // 4, p)
        if (sqrt * sqrt) % p == a % p:
            return sqrt
        else:
            return None
    else:
        # Use Tonelli-Shanks algorithm for general case
        return tonelli_shanks(a, p)

def tonelli_shanks(n, p):
    """Tonelli-Shanks algorithm for modular square roots."""
    # Check if n is a quadratic residue modulo p
    if pow(n, (p - 1) // 2, p) != 1:
        return None  # No square root exists

    # Find Q and S such that p - 1 = Q * 2^S with Q odd
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # Find a quadratic non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    c = pow(z, Q, p)
    R = pow(n, (Q + 1) // 2, p)
    t = pow(n, Q, p)
    M = S

    while t != 1:
        # Find the smallest i such that t^{2^i} = 1
        i = 1
        temp = (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
            if i == M:
                return None  # Should not happen

        b = pow(c, 1 << (M - i - 1), p)
        R = (R * b) % p
        c = (b * b) % p
        t = (t * c) % p
        M = i

    if (R * R) % p == n % p:
        return R
    else:
        return None



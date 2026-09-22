import random
import math


def gen_p():
    """
    Generate a random prime p in [100, 999].

    Keeps drawing random 3-digit candidates until one passes the
    Fermat primality test (is_prime). This range is a deliberate
    placeholder for hand-verifiable testing, not cryptographic size —
    scaling up later requires no changes here since Python ints
    aren't fixed-width.
    """
    p = random.randint(100, 999)
    while (is_prime(p) == False):
        p = random.randint(100, 999)
    return p


def gen_a(p):
    """
    Generate a random Fermat witness 'a' for testing primality of p.

    a must not be a multiple of p (a % p == 0 would make a ≡ 0 mod p,
    which trivially satisfies/breaks the test rather than actually
    testing anything). Drawn independently each time is_prime calls
    this — that independence is what lets repeated rounds compound
    the confidence of the test (see is_prime).
    """
    a = random.randint(100, 10000)
    while a % p == 0:
        a = random.randint(100, 10000)
    return a


def is_prime(p):
    """
    Probabilistic primality test for p, using Fermat's Little Theorem:
    if p is prime, then a^(p-1) ≡ 1 (mod p) for every a not divisible by p.

    The test can only prove compositeness, never prove primality:
    - If the congruence fails for some a, p is DEFINITELY composite
      (the implication prime ⟹ congruence is violated, so p can't be
      prime) — we return False immediately.
    - If the congruence holds, p is prime OR a happened to be a false
      witness for a composite p. A single pass is evidence, not proof.

    Running 10 independent, freshly-drawn witnesses (a new gen_a(p)
    call every iteration, not reused) shrinks the probability of
    being fooled by a composite exponentially with each additional
    round, the same way repeated independent trials compound in any
    probabilistic test.
    """
    for i in range(10):
        a = gen_a(p)
        if ((a ** (p - 1)) % p) != 1:
            flag = False
            break
        else:
            flag = True

    return flag


def key():
    """
    Generate two distinct primes p, q and compute n = p*q.

    p and q are regenerated (not just re-tested) until they differ,
    since RSA requires two DISTINCT primes — using p == q would break
    the phi(n) = (p-1)(q-1) formula, which relies on p, q being
    distinct primes with no common factors.
    """
    p = gen_p()
    q = gen_p()
    while (p == q):
        p = gen_p()
    n = p * q
    print(p, "*", q)
    return (p, q, n)


# print(key())


def totient(p, q):
    """
    Compute Euler's totient phi(n) for n = p*q, where p and q are
    distinct primes.

    phi(n) = (p-1)(q-1) — proved via inclusion-exclusion: count
    integers in [1,n] NOT coprime to n (multiples of p, multiples of
    q, minus the one number — n itself — that's a multiple of both),
    then subtract from n.

    Takes p, q as explicit parameters (rather than calling key()
    internally) so it always operates on ONE specific, already-
    generated keypair rather than accidentally mixing values from two
    independent random calls to key().
    """
    return (p - 1) * (q - 1)


def choose_e(p, q):
    """
    Choose a public exponent e satisfying gcd(e, phi(n)) = 1, which
    guarantees e has a multiplicative inverse mod phi(n) (needed to
    compute d).

    Searches in (1, phi(n)) — not because e is mathematically
    forbidden from being larger, but because it's pointless: for any
    e > phi(n), gcd(e, phi(n)) = gcd(e mod phi(n), phi(n)) (this falls
    directly out of the Euclidean algorithm's first reduction step),
    so every e above phi(n) is equivalent to some smaller e already
    covered by this range.
    """
    phi_n = totient(p, q)
    e = random.randint(1, phi_n)
    while math.gcd(phi_n, e) != 1:
        e = random.randint(1, phi_n)
    return e


def gcd(a, b):
    """
    Plain Euclidean algorithm: gcd(a,b) = gcd(b, a mod b), repeated
    until b hits 0.

    NOTE: currently unused — choose_e() uses the standard library's
    math.gcd instead. Kept here as the standalone building-block
    version worked through by hand before calc_d() below extended it
    to also track Bezout coefficients.
    """
    x = max(a, b)
    y = min(a, b)
    while y > 0:
        x, y = y, x % y
    return x


def calc_d(e, phi_n):
    """
    Compute d = e^-1 mod phi(n) via the extended Euclidean algorithm.

    Alongside the ordinary Euclidean (a, b) -> (b, a mod b) reduction,
    tracks coefficient pairs (s_a, t_a) and (s_b, t_b) satisfying the
    invariant "a = s_a*e + t_a*phi_n" (and same shape for b) at every
    step. This invariant is preserved by construction: since
    r = a - q*b, substituting the invariant expressions for a and b
    shows r = (s_a - q*s_b)*e + (t_a - q*t_b)*phi_n, i.e. the new
    remainder satisfies the same invariant with updated coefficients.

    When the loop ends (b == 0), a holds gcd(e, phi_n), which is 1 by
    construction (choose_e guarantees this). So the invariant becomes
    1 = s_a*e + t_a*phi_n. Reducing both sides mod phi_n makes the
    t_a*phi_n term vanish, leaving 1 ≡ s_a*e (mod phi_n) — exactly the
    definition of s_a being the modular inverse of e. s_a % phi_n
    reduces it into the proper [0, phi_n) range in case it came out
    negative.
    """
    a, b = e, phi_n
    s_a, t_a = 1, 0
    s_b, t_b = 0, 1

    while b > 0:
        q = a // b
        r = a % b
        s_r = s_a - q * s_b
        t_r = t_a - q * t_b

        a, b = b, r
        s_a, s_b = s_b, s_r
        t_a, t_b = t_b, t_r
    return s_a % phi_n


class RSAKeyPair:
    """
    Simple container bundling one complete RSA keypair's values
    (p, q, n, e, d) as attributes on a single object, so downstream
    functions (encrypt/decrypt, once written) can take one keypair
    argument instead of five separate loose values.
    """
    def __init__(self, p, q, n, e, d):
        self.p = p
        self.q = q
        self.n = n
        self.e = e
        self.d = d


def keygen():
    """
    Top-level orchestrator: runs the full key generation pipeline
    (generate primes -> compute n, phi(n) -> choose e -> compute d)
    and bundles the result into one RSAKeyPair instance.

    Deliberately a standalone function, not a method on RSAKeyPair —
    it CREATES an instance rather than operating on an existing one,
    so it has no natural "self" to receive.
    """
    (p, q, n) = key()
    phi_n = totient(p, q)
    e = choose_e(p, q)
    d = calc_d(e, phi_n)

    return RSAKeyPair(p, q, n, e, d)


kp = keygen()
print(kp.p, kp.q, kp.n, kp.e, kp.d)

# Correctness check: (e * d) mod phi(n) should equal 1 — this is the
# concrete instance of the proof in calc_d()'s docstring, verified on
# actual generated numbers rather than just trusted algebraically.
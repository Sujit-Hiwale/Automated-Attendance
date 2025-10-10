import os, base64, hashlib, requests
from argon2 import PasswordHasher, exceptions
from dotenv import load_dotenv

load_dotenv()
PEPPER = base64.b64decode(os.getenv("PEPPER_SECRET")) if os.getenv("PEPPER_SECRET") else None
HIBP_USER_AGENT = os.getenv("HIBP_USER_AGENT", "MyApp")

# Argon2 parameters (2025-acceptable baseline)
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)

def _apply_pepper(password: str) -> bytes:
    # combine pepper and password in memory, returns bytes
    if not PEPPER:
        return password.encode('utf-8')
    # use HMAC-like mixing to avoid concatenation ambiguity
    return hashlib.sha256(PEPPER + password.encode('utf-8')).digest()

def hash_password(password: str) -> str:
    mixed = _apply_pepper(password)
    # Argon2 expects str, so base64 the mixed bytes to a string
    return ph.hash(base64.b64encode(mixed).decode('ascii'))

def verify_password(stored_hash: str, attempt: str) -> bool:
    mixed = _apply_pepper(attempt)
    try:
        return ph.verify(stored_hash, base64.b64encode(mixed).decode('ascii'))
    except exceptions.VerifyMismatchError:
        return False

# HIBP check (k-anonymity)
def is_password_pwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": HIBP_USER_AGENT}
    r = requests.get(url, headers=headers, timeout=5)
    if r.status_code != 200:
        # treat remote failure as non-blocking; log alert
        return 0
    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0
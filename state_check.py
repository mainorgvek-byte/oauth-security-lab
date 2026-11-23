import hmac
import secrets


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def verify_state(expected: str, actual: str) -> bool:
    return hmac.compare_digest(expected, actual)


if __name__ == "__main__":
    s1 = generate_state()
    s2 = generate_state()
    print("s1:", s1)
    print("s2:", s2)
    print("distinct:", s1 != s2)
    print("valid:", verify_state(s1, s1), "invalid:", verify_state(s1, s2))

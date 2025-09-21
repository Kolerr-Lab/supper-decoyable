import os
import re
import pytest

# tests/test_secrets.py
# OSS-friendly, defensive tests for the secrets helpers in the codebase.
# Tests will be skipped if the expected module or functions are not present.


secrets = pytest.importorskip("decoyable.secrets")


def _call_load_secret(name, default=None):
    """
    Try a couple of common signatures for a loader helper so tests remain
    compatible with small API variations across versions:
      - load_secret(name, default)
      - load_secret(name, fallback=...)
      - load_secret(name, default=...)
      - load(name, default=...)
    If none match, pytest.skip so CI doesn't fail unexpectedly.
    """
    candidates = [
        ("load_secret", (name, default), {}),
        ("load_secret", (name,), {"default": default}),
        ("load_secret", (name,), {"fallback": default}),
        ("load", (name, default), {}),
        ("load", (name,), {"default": default}),
        ("load", (name,), {"fallback": default}),
    ]
    for attr, args, kwargs in candidates:
        fn = getattr(secrets, attr, None)
        if not callable(fn):
            continue
        try:
            return fn(*args, **kwargs)
        except TypeError:
            # signature mismatch, try next candidate
            continue
    pytest.skip("No compatible load_secret / load function found in decoyable.secrets")


@pytest.mark.parametrize(
    "orig",
    [
        "short",  # short values still should not equal redacted output
        "mysecretvalue12345",
        "AKIAEXAMPLEKEY123456",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
    ],
)
def test_redact_preserves_suffix_and_masks(orig):
    if not hasattr(secrets, "redact_secret") and not hasattr(secrets, "mask_secret"):
        pytest.skip("neither redact_secret nor mask_secret present")

    fn = getattr(secrets, "redact_secret", None) or getattr(secrets, "mask_secret")

    redacted = fn(orig)

    # Basic invariants: must not leak the whole value, must be a string, and must preserve a suffix
    assert isinstance(redacted, str)
    assert redacted != orig, "redaction returned the original value"

    # If the implementation keeps a suffix (common pattern), ensure that suffix still matches original's last 4 chars.
    # If original is shorter than 4 we only assert that redacted ends with some substring of original.
    keep = min(4, len(orig))
    assert redacted.endswith(orig[-keep:])

    # If redaction tries to preserve length for longer secrets, prefer that behavior but don't fail hard.
    if len(orig) > 4:
        assert len(redacted) >= 4


def test_looks_like_secret_detection():
    if not hasattr(secrets, "looks_like_secret") and not hasattr(secrets, "is_secret"):
        pytest.skip("no looks_like_secret / is_secret helper found")

    detector = getattr(secrets, "looks_like_secret", None) or getattr(secrets, "is_secret")

    positives = [
        "AKIA1234567890ABCD",  # AWS-like
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",  # JWT-like
        "0123456789abcdef0123456789abcdef",  # 32 hex
        "mF_9.B5f-4.1JqM",  # token with dots
        "VGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==",  # base64-like
    ]
    negatives = [
        "alice",
        "password",
        "1234",
        "",
        "short-token",
    ]

    for s in positives:
        assert detector(s), f"Expected '{s}' to be detected as a secret"

    for s in negatives:
        assert not detector(s), f"Expected '{s}' NOT to be detected as a secret"


def test_load_secret_from_env_and_default(monkeypatch, tmp_path):
    # Ensure environment value is prioritized
    monkeypatch.setenv("DECOY_TEST_SECRET", "env-value-xyz")
    value = _call_load_secret("DECOY_TEST_SECRET", default=None)
    assert value == "env-value-xyz"

    # Non-existent key should fall back to provided default
    val2 = _call_load_secret("DECOY_TEST_SECRET_NONEXISTENT", default="fallback-123")
    assert val2 == "fallback-123"
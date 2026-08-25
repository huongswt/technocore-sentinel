from src.identity import did_of, load_private_key, sign_message, sweep


def test_sweep_replaces_invisible_characters():
    assert sweep("  hello\nworld\u200b!  ") == "hello world !"


def test_did_shape_from_fixed_seed():
    key = load_private_key("00" * 32)
    did = did_of(key)
    assert did.startswith("did:key:z6Mk")
    assert len(did) == 56


def test_signature_is_unpadded_base64url():
    key = load_private_key("11" * 32)
    clean, sig = sign_message(key, "lobby", "1234567890123", "hello")
    assert clean == "hello"
    assert len(sig) == 86
    assert "=" not in sig

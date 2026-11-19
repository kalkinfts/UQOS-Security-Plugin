from neural_symbolic_projection import SMTDeltaPolicy, project
import hashlib
import pytest


def test_projection_is_deterministically_committed():
    kv = hashlib.sha256(b"kv").hexdigest()
    a = project(3, 0.22, "(assert (= lock true))", kv)
    b = project(3, 0.22, "(assert (= lock true))", kv)
    assert a.commitment == b.commitment


def test_projection_rejects_unbounded_or_unapproved_forms():
    kv = hashlib.sha256(b"kv").hexdigest()
    with pytest.raises(ValueError):
        project(3, 0.22, "(declare-fun evil () Int)", kv)


def test_projection_rejects_oversize_delta():
    kv = hashlib.sha256(b"kv").hexdigest()
    with pytest.raises(ValueError):
        project(3, 0.22, "(assert " + ("x" * 5000) + ")", kv)

"""Python bindings for ``libwabisabi`` — the WabiSabi KVAC anonymous-credential
protocol over secp256k1.

The public API is intentionally small:

* :class:`CredentialIssuer` — the stateful issuer (coordinator).
* :class:`Client` — the stateful client.
* :class:`Credential` — (de)serializes the wire credential format.
* :class:`WabiSabiError` — raised when the native library reports an error.

All wire bytes are interchangeable with the C# (`WabiSabi.Native`) and C
implementations: requests/responses/credentials produced here are accepted
there and vice-versa. The byte-oriented FFI plumbing lives in the private
:mod:`wabisabi._native` module and is not part of the public surface.

Example
-------
>>> import os
>>> from wabisabi import CredentialIssuer, Client
>>> sk = os.urandom(160)                 # demo only — derive a real key in production
>>> max_amount = 1 << 32
>>> issuer = CredentialIssuer(sk, max_amount)
>>> client = Client(issuer.iparams, max_amount)
>>> req, val = client.create_zero_request()
>>> resp = issuer.handle_zero(req)
>>> creds = client.handle_response(resp, val)
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import _native
from ._native import WabiSabiError

__all__ = ["Credential", "CredentialIssuer", "Client", "WabiSabiError"]

__version__ = "0.1.0"


# --------------------------------------------------------------------------
# Credential (de)serialization helpers
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Credential:
    """A single issued credential in its wire form.

    Layout (105 bytes):
    ``[value: 8 LE][randomness: 32][mac.t: 32][mac.V: 33]``.
    """

    value: int
    randomness: bytes  # 32-byte scalar (big-endian)
    mac_t: bytes       # 32-byte scalar (big-endian)
    mac_v: bytes       # 33-byte compressed group element

    def to_bytes(self) -> bytes:
        if len(self.randomness) != _native.SCALAR_SIZE:
            raise ValueError("randomness must be 32 bytes")
        if len(self.mac_t) != _native.SCALAR_SIZE:
            raise ValueError("mac_t must be 32 bytes")
        if len(self.mac_v) != _native.GE_SIZE:
            raise ValueError("mac_v must be 33 bytes")
        return (
            int(self.value).to_bytes(_native.VALUE_SIZE, "little", signed=True)
            + self.randomness
            + self.mac_t
            + self.mac_v
        )

    @classmethod
    def parse(cls, data: bytes) -> "Credential":
        if len(data) != _native.CREDENTIAL_SIZE:
            raise ValueError(
                f"credential must be {_native.CREDENTIAL_SIZE} bytes, got {len(data)}")
        value = int.from_bytes(data[:_native.VALUE_SIZE], "little", signed=True)
        off = _native.VALUE_SIZE
        randomness = data[off:off + _native.SCALAR_SIZE]; off += _native.SCALAR_SIZE
        mac_t = data[off:off + _native.SCALAR_SIZE]; off += _native.SCALAR_SIZE
        mac_v = data[off:off + _native.GE_SIZE]
        return cls(value, randomness, mac_t, mac_v)

    @staticmethod
    def pack(creds) -> bytes:
        """Serialize a sequence of :class:`Credential` to the packed wire format."""
        return b"".join(c.to_bytes() for c in creds)

    @staticmethod
    def unpack(data: bytes) -> "list[Credential]":
        """Parse packed credential bytes into a list of :class:`Credential`."""
        size = _native.CREDENTIAL_SIZE
        if len(data) % size != 0:
            raise ValueError("packed credential length is not a multiple of the credential size")
        return [Credential.parse(data[i:i + size]) for i in range(0, len(data), size)]


# --------------------------------------------------------------------------
# High-level stateful wrappers
# --------------------------------------------------------------------------

class CredentialIssuer:
    """Stateful issuer (coordinator) over the stateless native library.

    Holds the secret key, the value bound, and the serialized mutable issuer
    state (serial-number set + balance), advancing it on each request.

    Not thread-safe; guard with your own lock if shared across threads.
    """

    def __init__(self, sk_bytes: bytes, max_amount: int, rng=os.urandom):
        if len(sk_bytes) != _native.SK_SIZE:
            raise ValueError(f"sk_bytes must be {_native.SK_SIZE} bytes, got {len(sk_bytes)}")
        self._sk = bytes(sk_bytes)
        self.max_amount = int(max_amount)
        self._rng = rng
        self._mstate = b""  # initial state: balance = 0, no serials

    @property
    def iparams(self) -> bytes:
        """The 66-byte issuer parameters ``Cw || I`` for this secret key."""
        return _native.iparams_from_sk(self._sk)

    @property
    def balance(self) -> int:
        """Current issued balance (little-endian prefix of the mutable state)."""
        if len(self._mstate) < 8:
            return 0
        return int.from_bytes(self._mstate[:8], "little", signed=True)

    @property
    def mstate(self) -> bytes:
        """Opaque serialized mutable state (persist this to resume later)."""
        return self._mstate

    @mstate.setter
    def mstate(self, value: bytes) -> None:
        self._mstate = bytes(value or b"")

    def handle_zero(self, request_bytes: bytes) -> bytes:
        """Process a zero (bootstrap) request, advance state, return the response."""
        resp, self._mstate = _native.issuer_handle_zero(
            self._sk, self.max_amount, self._mstate,
            request_bytes, self._rng(_native.RAND_SIZE))
        return resp

    def handle_real(self, request_bytes: bytes) -> bytes:
        """Process a real request, advance state, return the response."""
        resp, self._mstate = _native.issuer_handle_real(
            self._sk, self.max_amount, self._mstate,
            request_bytes, self._rng(_native.RAND_SIZE))
        return resp


class Client:
    """Stateful client over the stateless native library.

    Each ``create_*`` call returns ``(request_bytes, validation_state)``; pass
    the same ``validation_state`` back into :meth:`handle_response` to extract
    the issued credentials.
    """

    def __init__(self, iparams_bytes: bytes, max_amount: int, rng=os.urandom):
        if len(iparams_bytes) != _native.IPARAMS_SIZE:
            raise ValueError(
                f"iparams_bytes must be {_native.IPARAMS_SIZE} bytes, got {len(iparams_bytes)}")
        self._iparams = bytes(iparams_bytes)
        self.max_amount = int(max_amount)
        self._rng = rng

    def create_zero_request(self):
        """Create a bootstrap request. Returns ``(request_bytes, validation_state)``."""
        return _native.client_create_zero_request(self._rng(_native.RAND_SIZE))

    def create_real_request(self, amounts, credentials_to_present=()):
        """Create a real request presenting existing credentials.

        ``amounts`` is a sequence of ints to request; ``credentials_to_present``
        is a sequence of :class:`Credential` (or raw packed bytes).
        Returns ``(request_bytes, validation_state)``.
        """
        if isinstance(credentials_to_present, (bytes, bytearray)):
            creds_bytes = bytes(credentials_to_present)
            n_creds = len(creds_bytes) // _native.CREDENTIAL_SIZE
        else:
            creds = list(credentials_to_present)
            creds_bytes = Credential.pack(creds)
            n_creds = len(creds)
        return _native.client_create_real_request(
            self._iparams, self.max_amount,
            list(amounts), creds_bytes, n_creds, self._rng(_native.RAND_SIZE))

    def handle_response(self, response_bytes: bytes, validation_state: bytes):
        """Validate a response and return the issued credentials as a list."""
        packed = _native.client_handle_response(self._iparams, response_bytes, validation_state)
        return Credential.unpack(packed)

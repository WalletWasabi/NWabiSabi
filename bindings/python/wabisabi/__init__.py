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
from enum import IntEnum

from . import _native
from ._native import WabiSabiError

__all__ = [
    "Credential",
    "CredentialIssuer",
    "Client",
    "OwnershipProof",
    "OwnershipScriptPubKeyType",
    "WabiSabiError",
]

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
    state (the running balance), advancing it on each request.

    Double-spend prevention: the native library performs only cryptographic
    verification and balance bookkeeping and does NOT remember serial numbers
    between calls, so this wrapper tracks the serial numbers of accepted
    presentations in memory and rejects a request that replays one. (The native
    library still rejects a request that presents the same serial twice within a
    single request.) This mirrors the C# ``WabiSabi.Native.CredentialIssuer`` and
    the managed reference. The serial set is in-memory only — like the reference
    it is not part of the persistable :attr:`mstate`; a coordinator that resumes
    from a persisted ``mstate`` after a restart must persist and restore its own
    serial set too, or it will accept replays of pre-restart credentials.

    Not thread-safe; guard with your own lock if shared across threads.
    """

    def __init__(self, sk_bytes: bytes, max_amount: int, rng=os.urandom):
        if len(sk_bytes) != _native.SK_SIZE:
            raise ValueError(f"sk_bytes must be {_native.SK_SIZE} bytes, got {len(sk_bytes)}")
        self._sk = bytes(sk_bytes)
        self.max_amount = int(max_amount)
        self._rng = rng
        self._mstate = b""  # initial state: balance = 0
        self._serials: set[bytes] = set()  # serial numbers of accepted presentations

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
        """Opaque serialized mutable state — the balance (persist to resume later).

        Note this does NOT include the serial-number set (see the class docs);
        persisting double-spend state across a restart is the caller's job.
        """
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
        """Process a real request, advance state, return the response.

        Rejects a request that replays a serial number accepted by an earlier
        request (raises :class:`WabiSabiError` with the SERIAL_REUSED code)
        before touching the native library; serials of an accepted request are
        recorded only after the native call succeeds.
        """
        serials = self._presented_serials(request_bytes)
        for s in serials:
            if s in self._serials:
                raise WabiSabiError(_native.WABISABI_ERR_SERIAL_REUSED, "issuer_handle_real")

        # Raises WabiSabiError on any native rejection (bad proofs, negative
        # balance, or a within-request duplicate serial), leaving _serials
        # untouched — so nothing is committed for a rejected request.
        resp, self._mstate = _native.issuer_handle_real(
            self._sk, self.max_amount, self._mstate,
            request_bytes, self._rng(_native.RAND_SIZE))
        self._serials.update(serials)
        return resp

    @staticmethod
    def _presented_serials(request_bytes: bytes) -> "list[bytes]":
        """Extract the presented serial numbers (S) from a real-request blob.

        RealRequest layout is ``[delta:8][presentation_0]...[presentation_{k-1}]...``
        where each presentation is ``[Ca][Cx0][Cx1][CV][S]`` of GE_SIZE-byte group
        elements; the serial number S is the last one. Returns ``[]`` if the blob
        is too short to parse (the native call then rejects it and reports why).
        """
        serials: list[bytes] = []
        off = _native.VALUE_SIZE                # skip the 8-byte delta
        s_off = 4 * _native.GE_SIZE             # S is the 5th group element
        for _ in range(_native.CREDENTIAL_COUNT):
            end = off + _native.PRESENTATION_SIZE
            if end > len(request_bytes):
                return []
            serials.append(request_bytes[off + s_off:end])
            off = end
        return serials


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


# --------------------------------------------------------------------------
# Ownership proofs (SLIP-0019 / BIP-322)
# --------------------------------------------------------------------------

class OwnershipScriptPubKeyType(IntEnum):
    """The scriptPubKey type an ownership proof is generated for.

    Kept independent of any Bitcoin library: a caller that has one maps its own
    script-type onto these values. Mirrors the C ``wabisabi_spk_type_t`` and the
    C# ``OwnershipScriptPubKeyType`` enums.
    """

    SEGWIT = _native.SPK_P2WPKH        #: Segwit v0 (P2WPKH).
    TAPROOT_BIP86 = _native.SPK_P2TR   #: Taproot key-path, BIP-86 (P2TR).


class OwnershipProof:
    """SLIP-0019 / BIP-322 ownership proofs, byte-for-byte compatible with
    WalletWasabi's managed ``OwnershipProof`` and the C# ``WabiSabi.Native``
    facade.

    Proving ownership of a coin means demonstrating control of the private key
    that can spend its scriptPubKey. Generation derives the scriptPubKey
    natively from the key and type; verification is done by a party that only
    holds the coin's scriptPubKey (not the key). This class carries no state —
    both methods are static.
    """

    #: Length in bytes of a single ownership identifier (HMAC-SHA256 output).
    OWNERSHIP_ID_LENGTH = _native.OWNERSHIP_ID_SIZE

    #: Required length in bytes of a private key.
    PRIVKEY_LENGTH = _native.PRIVKEY_SIZE

    @staticmethod
    def generate(
        key: bytes,
        commitment_data: bytes = b"",
        ownership_identifiers=(),
        script_pubkey_type: OwnershipScriptPubKeyType = OwnershipScriptPubKeyType.SEGWIT,
        user_confirmation: bool = True,
    ) -> bytes:
        """Generate a serialized ownership proof for the coin owned by ``key``.

        ``key`` is the 32-byte private key; the scriptPubKey is derived natively
        from it and ``script_pubkey_type``. ``commitment_data`` is bound into the
        signature hash (e.g. the CoinJoin input commitment; may be empty).
        ``ownership_identifiers`` is a sequence of 32-byte identifiers.
        ``user_confirmation`` sets the UserConfirmation flag (true for CoinJoin
        input proofs). Returns the serialized proof, identical to WalletWasabi's
        ``OwnershipProof.ToBytes()``.
        """
        if len(key) != OwnershipProof.PRIVKEY_LENGTH:
            raise ValueError(
                f"key must be {OwnershipProof.PRIVKEY_LENGTH} bytes, got {len(key)}")

        flat = OwnershipProof._flatten_identifiers(ownership_identifiers)
        return _native.ownership_proof_generate(
            key,
            int(script_pubkey_type),
            flat,
            commitment_data or b"",
            user_confirmation,
        )

    @staticmethod
    def verify(
        proof: bytes,
        script_pubkey: bytes,
        commitment_data: bytes = b"",
        require_user_confirmation: bool = False,
    ) -> bool:
        """Verify a serialized ownership proof against a coin's scriptPubKey.

        The verifier does not need the private key. ``commitment_data`` must
        match what the proof was bound to. ``require_user_confirmation`` rejects
        proofs lacking the UserConfirmation flag. Returns ``True`` if valid,
        ``False`` if the signature or flags do not verify; raises
        :class:`WabiSabiError` if the proof is malformed.
        """
        return _native.ownership_proof_verify(
            proof, script_pubkey, commitment_data or b"", require_user_confirmation)

    @staticmethod
    def _flatten_identifiers(ownership_identifiers) -> bytes:
        if isinstance(ownership_identifiers, (bytes, bytearray)):
            data = bytes(ownership_identifiers)
            if len(data) % OwnershipProof.OWNERSHIP_ID_LENGTH != 0:
                raise ValueError(
                    "packed identifiers length must be a multiple of "
                    f"{OwnershipProof.OWNERSHIP_ID_LENGTH}")
            return data

        flat = bytearray()
        for identifier in ownership_identifiers:
            if len(identifier) != OwnershipProof.OWNERSHIP_ID_LENGTH:
                raise ValueError(
                    "each ownership identifier must be "
                    f"{OwnershipProof.OWNERSHIP_ID_LENGTH} bytes, got {len(identifier)}")
            flat += identifier
        return bytes(flat)

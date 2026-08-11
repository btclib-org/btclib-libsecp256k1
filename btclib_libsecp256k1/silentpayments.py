# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Silent Payments.

According to BIP352:
https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

What libsecp256k1 implements, and therefore what is wrapped here, is the
elliptic curve half of the protocol: the sum of the input keys, the
Diffie-Hellman shared secret, and the outputs and tweaks derived from it.
Addresses, output script types and transaction parsing are not part of
it -- which is why every function here takes keys and a serialized
outpoint rather than a transaction, and why deciding which inputs are
eligible, and which of the eligible ones are taproot, is the caller's:
BIP352 states those rules over scripts, and there is no script here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from . import BytesLike, CData, ffi, lib
from ._scalar import octets, scalar
from ._secret import take, wipe
from .context import ctx
from .keys import serialize

# the two widths this module has to check, neither of them a macro that
# survives the preprocessing of the headers into cffi definitions. The
# summary's is asked of the struct rather than written down, so that a
# libsecp256k1 that changes it changes this too; the label's is the 33
# bytes of a compressed point, which is its serialization and not the 68
# of the object holding it
SUMMARY_SIZE = ffi.sizeof("secp256k1_silentpayments_prevouts_summary")
LABEL_SIZE = 33


def create_outputs(
    recipients: Sequence[tuple[BytesLike, BytesLike]],
    outpoint_smallest36: BytesLike,
    taproot_prvkeys: Sequence[BytesLike | int] = (),
    prvkeys: Sequence[BytesLike | int] = (),
) -> list[bytes]:
    """Create the taproot outputs paying a list of Silent Payments addresses.

    This is the sender's side, and it needs the private keys of every
    input the payment is funded from: the shared secret is derived from
    their sum. Which inputs are eligible is BIP352's rule over their
    scripts and so the caller's to apply, as is the split below -- a
    taproot input contributes the key of its even-y point, which is why
    its private key goes to `taproot_prvkeys` and not to `prvkeys`.

    All the outputs returned must appear in the transaction. Dropping one
    can make the others unfindable by their recipient, the derivation
    being over the whole set.

    Args:
        recipients: the addresses to pay, each a pair of the recipient's
            scan and spend public keys, 33 or 65 bytes each. The same
            address may appear more than once, which pays it that many
            outputs. At least one is required.
        outpoint_smallest36: the 36-byte serialization of the
            lexicographically smallest outpoint of *all* the transaction
            inputs, eligible or not. Choosing it is the caller's, and
            choosing it wrongly makes the payment unfindable rather than
            invalid -- BIP352's own vectors are what to check an
            implementation of that against.
        taproot_prvkeys: the private keys of the taproot inputs, 32
            bytes or an int below 2**256 each.
        prvkeys: the private keys of the other eligible inputs.

    Returns:
        The 32-byte x-only public key of one taproot output per
        recipient, in the order the recipients were given.

    Raises:
        ValueError: if no recipient or no private key is given, if the
            outpoint is not 36 bytes, if any public key is not a valid
            point, if any private key is not 32 bytes, does not fit in
            them, or is not in [1, n-1], or if libsecp256k1 refuses the
            set -- the sum of the private keys being zero, an output
            landing on an invalid point, or more outputs asked of one
            scan key than BIP352 allows it.

    Example:
        >>> from btclib_libsecp256k1 import keys, silentpayments
        >>> scan_pubkey = keys.pubkey_from_prvkey(1)
        >>> spend_pubkey = keys.pubkey_from_prvkey(2)
        >>> outputs = silentpayments.create_outputs(
        ...     [(scan_pubkey, spend_pubkey)], bytes(36), prvkeys=[3]
        ... )
        >>> len(outputs), len(outputs[0])
        (1, 32)
    """
    if not recipients:
        raise ValueError("at least one recipient is required")
    if not taproot_prvkeys and not prvkeys:
        raise ValueError("at least one private key is required")
    outpoint_smallest36 = octets(outpoint_smallest36, "smallest outpoint", 36)

    recipient_objs = [
        _recipient(scan_pubkey_bytes, spend_pubkey_bytes, index)
        for index, (scan_pubkey_bytes, spend_pubkey_bytes) in enumerate(recipients)
    ]
    outputs = [ffi.new("secp256k1_xonly_pubkey *") for _ in recipient_objs]

    # the two key lists are built inside the try, not before it: each
    # element carries a private key and the next one can raise, so what
    # wipes them has to already be in force while they are being made
    keypairs: list[CData] = []
    seckeys: list[CData] = []
    try:
        keypairs.extend(_keypair(prvkey) for prvkey in taproot_prvkeys)
        seckeys.extend(
            ffi.new("unsigned char[32]", scalar(prvkey, "private key"))
            for prvkey in prvkeys
        )
        created = lib.secp256k1_silentpayments_sender_create_outputs(
            ctx,
            ffi.new("secp256k1_xonly_pubkey *[]", outputs),
            # the array holds borrowed pointers: the list above is what
            # keeps the recipients it points to alive, and libsecp256k1
            # reorders the array rather than the objects
            ffi.new("secp256k1_silentpayments_recipient *[]", recipient_objs),
            len(recipient_objs),
            outpoint_smallest36,
            _array("secp256k1_keypair *[]", keypairs),
            len(keypairs),
            _array("unsigned char *[]", seckeys),
            len(seckeys),
        )
    finally:
        for buffer in (*keypairs, *seckeys):
            wipe(buffer)

    if not created:
        raise ValueError("silent payment output creation failed")
    return [_serialize_xonly(output) for output in outputs]


def label(scan_prvkey: BytesLike | int, m: int) -> tuple[bytes, bytes]:
    """Create the m-th label of a scan key, and its tweak.

    A label lets one scan key receive at more than one address: the
    recipient publishes `labeled_spend_pubkey` instead of the spend
    public key, and hands the label back to `scan_outputs` so that an
    output paid to it is recognized. BIP352 reserves m = 0 for change.

    Labels cost interoperability and, in a light client, scanning speed:
    BIP352 recommends creating the change label and no other, and
    distributing the unlabeled address.

    Args:
        scan_prvkey: the recipient's scan private key, 32 bytes or an
            int below 2**256.
        m: which label, an int below 2**32. Zero is BIP352's change
            label.

    Returns:
        The 33-byte label, which is what `scan_outputs` is keyed on, and
        the 32-byte tweak, which is the secret that spends what was paid
        to it.

    Raises:
        ValueError: if m is out of range, or if the scan key is not 32
            bytes, does not fit in them, or is not in [1, n-1].

    Example:
        >>> from btclib_libsecp256k1 import silentpayments
        >>> label, tweak = silentpayments.label(1, 0)
        >>> len(label), len(tweak)
        (33, 32)
    """
    scan_prvkey_bytes = scalar(scan_prvkey, "scan private key")
    # uint32_t: cffi would answer an out of range m with OverflowError,
    # which is not how this package reports an argument out of domain
    if not 0 <= m < 2**32:
        raise ValueError("the label m must fit in 4 bytes")

    label_obj = ffi.new("secp256k1_silentpayments_label *")
    tweak = ffi.new("char[32]")
    if not lib.secp256k1_silentpayments_recipient_label_create(
        ctx, label_obj, tweak, scan_prvkey_bytes, m
    ):
        # the hash landing outside [1, n-1] is the other way this fails,
        # and it has never been reached: it is negligible per evaluation
        raise ValueError("invalid scan private key")
    return _serialize_label(label_obj), take(tweak)


def labeled_spend_pubkey(
    spend_pubkey_bytes: BytesLike, label_bytes: BytesLike, compressed: bool = True
) -> bytes:
    """Add a label to a spend public key.

    The result is the spend public key of the Silent Payments address
    that `label` opens: an address is the recipient's scan public key and
    this key, and what makes them different addresses of one scan key is
    this sum.

    Args:
        spend_pubkey_bytes: the recipient's unlabeled spend public key,
            33 or 65 bytes.
        label_bytes: the 33-byte label, as `label` returns it.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized labeled spend public key.

    Raises:
        ValueError: if the spend public key is not a valid point, if the
            label is not 33 bytes or is not one, or if the two sum to
            the point at infinity, which has no serialization and which
            a label BIP352 made cannot produce.
        RuntimeError: if libsecp256k1 fails to serialize the result,
            which no valid input can make it do.

    Example:
        >>> from btclib_libsecp256k1 import keys, silentpayments
        >>> spend_pubkey = keys.pubkey_from_prvkey(2)
        >>> label, _ = silentpayments.label(1, 0)
        >>> len(silentpayments.labeled_spend_pubkey(spend_pubkey, label))
        33
    """
    spend_pubkey = _pubkey(spend_pubkey_bytes, "spend public key")
    label_obj = _parse_label(label_bytes)

    labeled = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
        ctx, labeled, spend_pubkey, label_obj
    ):
        raise ValueError("invalid labeled spend public key")
    return serialize(labeled, compressed)


def prevouts_summary(
    outpoint_smallest36: BytesLike,
    taproot_pubkeys: Sequence[BytesLike] = (),
    pubkeys: Sequence[BytesLike] = (),
) -> bytes:
    """Summarize the inputs of a transaction, for scanning it.

    This is what the recipient's side needs of a transaction, and all of
    it: the sum of its eligible input public keys and the hash of its
    smallest outpoint, computed once and handed to `scan_outputs` for
    every scan key that scans the transaction.

    The keys are split the way BIP352 reads them: a taproot input
    contributes the even-y point of its 32-byte x-only key, any other
    eligible input the full key its script commits to.

    Args:
        outpoint_smallest36: the 36-byte serialization of the
            lexicographically smallest outpoint of all the transaction
            inputs, eligible or not.
        taproot_pubkeys: the 32-byte x-only public keys of the taproot
            inputs.
        pubkeys: the public keys of the other eligible inputs, 33 or 65
            bytes each.

    Returns:
        The summary, as the bytes libsecp256k1 holds it in. They are
        opaque, they are not a serialization -- what is inside is
        libsecp256k1's own and portable across neither platforms nor
        versions -- and the only thing to do with them is to hand them
        to `scan_outputs` in the same process. They hold no secret.

    Raises:
        ValueError: if no public key is given, if the outpoint is not 36
            bytes, if any key is not a valid point, or if the inputs sum
            to the point at infinity, which is BIP352's "not a Silent
            Payments transaction" and which the recipient skips.

    Example:
        >>> from btclib_libsecp256k1 import keys, silentpayments
        >>> summary = silentpayments.prevouts_summary(
        ...     bytes(36), pubkeys=[keys.pubkey_from_prvkey(3)]
        ... )
        >>> len(summary) == silentpayments.SUMMARY_SIZE
        True
    """
    if not taproot_pubkeys and not pubkeys:
        raise ValueError("at least one public key is required")
    outpoint_smallest36 = octets(outpoint_smallest36, "smallest outpoint", 36)

    xonly_pubkeys = [
        _xonly_pubkey(pubkey_bytes, "taproot public key")
        for pubkey_bytes in taproot_pubkeys
    ]
    full_pubkeys = [_pubkey(pubkey_bytes, "public key") for pubkey_bytes in pubkeys]

    summary = ffi.new("secp256k1_silentpayments_prevouts_summary *")
    if not lib.secp256k1_silentpayments_recipient_prevouts_summary_create(
        ctx,
        summary,
        outpoint_smallest36,
        _array("secp256k1_xonly_pubkey *[]", xonly_pubkeys),
        len(xonly_pubkeys),
        _array("secp256k1_pubkey *[]", full_pubkeys),
        len(full_pubkeys),
    ):
        raise ValueError("not a silent payments transaction")
    return bytes(ffi.buffer(summary))


def scan_outputs(
    tx_outputs: Sequence[BytesLike],
    scan_prvkey: BytesLike | int,
    summary_bytes: BytesLike,
    spend_pubkey_bytes: BytesLike,
    labels: Mapping[bytes, BytesLike] | None = None,
) -> list[tuple[bytes, bytes, bytes | None]]:
    """Find the outputs of a transaction that pay a Silent Payments address.

    This is the recipient's side. It needs the scan private key, because
    the shared secret is derived from it, and the *unlabeled* spend
    public key even where the address published was a labeled one:
    what a label changes is the address, not what is scanned for.

    Args:
        tx_outputs: the 32-byte x-only public keys of the transaction's
            taproot outputs, in vout order. At least one is required.
        scan_prvkey: the recipient's scan private key, 32 bytes or an
            int below 2**256.
        summary_bytes: the summary of the transaction's inputs, as
            `prevouts_summary` returned it.
        spend_pubkey_bytes: the recipient's unlabeled spend public key,
            33 or 65 bytes.
        labels: the recipient's label cache, mapping each 33-byte label
            to its 32-byte tweak, or None where no labeled address was
            published. Only a label in here can be found: BIP352 makes
            recognizing one a lookup rather than a computation, and this
            is that lookup. The keys are bytes and only bytes, unlike
            every other argument here: a `bytearray` and a `memoryview`
            are what a mapping cannot be keyed on, being unhashable.

    Returns:
        One triple per output found, in vout order: its 32-byte x-only
        public key, the 32-byte tweak to add to the spend private key to
        spend it, and the 33-byte label it was found with, or None where
        it was paid to the unlabeled address. An empty list where the
        transaction pays this address nothing.

    Raises:
        ValueError: if no output is given, if any of them is not a valid
            x-only public key, if the scan key is not 32 bytes, does not
            fit in them, or is not in [1, n-1], if the summary is not
            the right length, if the spend public key is not a valid
            point, if a label or a label tweak is the wrong length, or
            if libsecp256k1 refuses the scan.

    Example:
        >>> from btclib_libsecp256k1 import keys, silentpayments
        >>> scan_pubkey = keys.pubkey_from_prvkey(1)
        >>> spend_pubkey = keys.pubkey_from_prvkey(2)
        >>> outputs = silentpayments.create_outputs(
        ...     [(scan_pubkey, spend_pubkey)], bytes(36), prvkeys=[3]
        ... )
        >>> summary = silentpayments.prevouts_summary(
        ...     bytes(36), pubkeys=[keys.pubkey_from_prvkey(3)]
        ... )
        >>> found = silentpayments.scan_outputs(
        ...     outputs, 1, summary, spend_pubkey
        ... )
        >>> [pubkey for pubkey, _tweak, _label in found] == outputs
        True
    """
    if not tx_outputs:
        raise ValueError("at least one transaction output is required")
    scan_prvkey_bytes = scalar(scan_prvkey, "scan private key")
    summary_bytes = octets(summary_bytes, "prevouts summary", SUMMARY_SIZE)
    spend_pubkey = _pubkey(spend_pubkey_bytes, "spend public key")

    output_objs = [
        _xonly_pubkey(pubkey_bytes, "transaction output") for pubkey_bytes in tx_outputs
    ]
    # the summary is opaque both ways: what came out of prevouts_summary
    # is written straight back into a struct of the same size, there
    # being no parser for it and nothing here that reads it
    summary = ffi.new("secp256k1_silentpayments_prevouts_summary *")
    ffi.buffer(summary)[:] = summary_bytes
    # the found outputs array is as long as the outputs one, as the
    # header requires, and libsecp256k1 says through n_found how much of
    # it it wrote
    found_objs = [
        ffi.new("secp256k1_silentpayments_found_output *") for _ in output_objs
    ]
    n_found = ffi.new("uint32_t *")

    cache = _label_cache(labels)
    try:
        scanned = lib.secp256k1_silentpayments_recipient_scan_outputs(
            ctx,
            ffi.new("secp256k1_silentpayments_found_output *[]", found_objs),
            n_found,
            ffi.new("secp256k1_xonly_pubkey *[]", output_objs),
            len(output_objs),
            scan_prvkey_bytes,
            summary,
            spend_pubkey,
            # a NULL lookup is how libsecp256k1 is told no label is in
            # play, and it is not the same as one that never matches:
            # with it the scan skips the label branch altogether
            ffi.NULL
            if cache is None
            else ffi.callback("secp256k1_silentpayments_label_lookup", _lookup(cache)),
            ffi.NULL,
        )
        if not scanned:
            raise ValueError("silent payment scanning failed")
        return [_found_output(found) for found in found_objs[: n_found[0]]]
    finally:
        # every found output carries the tweak that spends it, and the
        # cache the tweaks of the labels: both are secrets in memory this
        # package owns, and so both are taken back
        for buffer in (*found_objs, *(cache or {}).values()):
            wipe(buffer)


def _label_cache(
    labels: Mapping[bytes, BytesLike] | None,
) -> dict[bytes, CData] | None:
    """Copy a label cache into the buffers the lookup will hand back.

    Every tweak is copied into memory this package owns before the scan
    starts, rather than inside the callback: the pointer returned from
    there has to stay valid until libsecp256k1 is done with it, and a
    buffer made on the way out would be owned by nothing.

    Args:
        labels: the caller's mapping of 33-byte labels to 32-byte
            tweaks, or None.

    Returns:
        The same mapping with each tweak in a cffi buffer, or None where
        None was given -- which is not an empty cache but the absence of
        one, and reaches libsecp256k1 as a NULL lookup function.

    Raises:
        TypeError: if a label or a tweak is not bytes.
        ValueError: if a label is not 33 bytes, or a tweak not 32.
    """
    if labels is None:
        return None
    return {
        octets(label_bytes, "label", LABEL_SIZE): ffi.new(
            "unsigned char[32]", octets(tweak_bytes, "label tweak", 32)
        )
        for label_bytes, tweak_bytes in labels.items()
    }


def _lookup(cache: dict[bytes, CData]) -> Callable[[CData, CData], CData]:
    """Build the label lookup libsecp256k1 calls back into.

    Args:
        cache: the labels of `_label_cache`, keyed on their 33 bytes.

    Returns:
        A function of the C signature libsecp256k1 declares. It cannot
        raise -- a `dict.get` over keys already normalized -- which
        matters because cffi has nowhere to put an exception raised
        inside a callback: it prints the traceback and returns a default,
        so a lookup that could raise would answer "no label" while
        looking like it worked.
    """

    def lookup(label33: CData, label_context: CData) -> CData:
        return cache.get(bytes(ffi.buffer(label33, LABEL_SIZE)), ffi.NULL)

    return lookup


def _found_output(found: CData) -> tuple[bytes, bytes, bytes | None]:
    """Read one found output out of the struct libsecp256k1 wrote it in.

    Args:
        found: the `secp256k1_silentpayments_found_output` object.

    Returns:
        Its 32-byte x-only public key, its 32-byte tweak, and its
        33-byte label where it has one. The struct is left as it is: the
        caller wipes it, the tweak being a secret and the caller being
        what already wipes the ones that were not written to.

    Raises:
        RuntimeError: if libsecp256k1 fails to serialize either, which
            an output it produced cannot make it do.
    """
    pubkey = _serialize_xonly(ffi.addressof(found, "output"))
    tweak = bytes(ffi.buffer(found.tweak))
    if not found.found_with_label:
        return pubkey, tweak, None
    return pubkey, tweak, _serialize_label(ffi.addressof(found, "label"))


def _array(cdecl: str, items: list[CData]) -> CData:
    """Build the array of borrowed pointers libsecp256k1 takes, or NULL.

    Args:
        cdecl: the cffi declaration of the array type.
        items: the objects to point at, which the caller keeps alive.

    Returns:
        The array, or NULL where there is nothing to point at: that is
        what the header asks for, and cffi will not make an array of
        length zero to pass instead.
    """
    return ffi.new(cdecl, items) if items else ffi.NULL


def _recipient(
    scan_pubkey_bytes: BytesLike, spend_pubkey_bytes: BytesLike, index: int
) -> CData:
    """Build one recipient of `create_outputs`.

    Args:
        scan_pubkey_bytes: the recipient's scan public key, 33 or 65
            bytes.
        spend_pubkey_bytes: the recipient's spend public key, labeled or
            not -- which of the two it is the sender neither knows nor
            needs to.
        index: the position of this recipient among them, which is what
            libsecp256k1 orders the outputs it returns by.

    Returns:
        The libsecp256k1 recipient object.

    Raises:
        ValueError: if either key is not a valid point.
    """
    recipient = ffi.new("secp256k1_silentpayments_recipient *")
    # assigning a struct to a struct field copies it, so the parsed keys
    # need not outlive this call
    recipient.scan_pubkey = _pubkey(scan_pubkey_bytes, "scan public key")[0]
    recipient.spend_pubkey = _pubkey(spend_pubkey_bytes, "spend public key")[0]
    recipient.index = index
    return recipient


def _pubkey(pubkey_bytes: BytesLike, name: str) -> CData:
    """Parse a public key, named as the exception should call it.

    `keys.parse` is the same call and says "public key"; this module
    passes four kinds of them -- scan, spend, taproot input, other input
    -- and which one was refused is the whole of what the caller needs.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.
        name: what the key is, as the exception should call it.

    Returns:
        The libsecp256k1 public key object.

    Raises:
        ValueError: if the bytes are not a valid point in either
            serialization.
    """
    pubkey_bytes = octets(pubkey_bytes, name)
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError(f"invalid {name}")
    return pubkey


def _xonly_pubkey(pubkey_bytes: BytesLike, name: str) -> CData:
    """Parse a 32-byte x-only public key, named as the exception calls it.

    Args:
        pubkey_bytes: the 32-byte x coordinate.
        name: what the key is, as the exception should call it.

    Returns:
        The libsecp256k1 x-only public key object.

    Raises:
        ValueError: if it is not 32 bytes, or not a valid x coordinate.
    """
    # secp256k1_xonly_pubkey_parse takes a bare pointer to 32 bytes
    pubkey_bytes = octets(pubkey_bytes, name, 32)
    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    if not lib.secp256k1_xonly_pubkey_parse(ctx, xonly_pubkey, pubkey_bytes):
        raise ValueError(f"invalid {name}")
    return xonly_pubkey


def _serialize_xonly(xonly_pubkey: CData) -> bytes:
    """Serialize an x-only public key libsecp256k1 produced.

    Args:
        xonly_pubkey: the libsecp256k1 x-only public key object.

    Returns:
        Its 32-byte x coordinate.

    Raises:
        RuntimeError: if libsecp256k1 fails to serialize it, which a key
            it produced cannot make it do.
    """
    output = ffi.new("char[32]")
    if not lib.secp256k1_xonly_pubkey_serialize(ctx, output, xonly_pubkey):
        raise RuntimeError("x-only public key serialization failed")
    return ffi.unpack(output, ffi.sizeof(output))


def _parse_label(label_bytes: BytesLike) -> CData:
    """Parse a 33-byte label.

    Args:
        label_bytes: the label, as `label` returned it.

    Returns:
        The libsecp256k1 label object.

    Raises:
        ValueError: if it is not 33 bytes, or not a valid point.
    """
    label_bytes = octets(label_bytes, "label", LABEL_SIZE)
    label_obj = ffi.new("secp256k1_silentpayments_label *")
    if not lib.secp256k1_silentpayments_recipient_label_parse(
        ctx, label_obj, label_bytes
    ):
        raise ValueError("invalid label")
    return label_obj


def _serialize_label(label_obj: CData) -> bytes:
    """Serialize a label libsecp256k1 produced.

    Args:
        label_obj: the libsecp256k1 label object.

    Returns:
        Its 33 bytes, which are the compressed point it is.

    Raises:
        RuntimeError: if libsecp256k1 fails to serialize it, which a
            label it produced cannot make it do.
    """
    output = ffi.new(f"char[{LABEL_SIZE}]")
    if not lib.secp256k1_silentpayments_recipient_label_serialize(
        ctx, output, label_obj
    ):
        raise RuntimeError("label serialization failed")
    return ffi.unpack(output, ffi.sizeof(output))


def _keypair(prvkey: BytesLike | int) -> CData:
    """Create a keypair from a private key.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        The libsecp256k1 keypair object.

    Raises:
        ValueError: if the key is not 32 bytes, does not fit in them, or
            is not in [1, n-1].
    """
    keypair = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(ctx, keypair, scalar(prvkey, "private key")):
        raise ValueError("invalid private key")
    return keypair

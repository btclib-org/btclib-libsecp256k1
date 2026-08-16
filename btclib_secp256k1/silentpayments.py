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

This is the module with the most keys to parse per call, and so the one
where the private halves earn the most: a wallet scanning block after
block parses each of its own keys once and hands the objects to
`_scan_outputs_`, where `scan_outputs` parses the spend key and every
transaction output again at every transaction.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from . import BytesLike, CData, ffi, keys, lib, xonly
from ._cdata import array
from ._scalar import in_range, octets, scalar
from ._secret import keypair, take, wipe
from .context import ctx

# the two widths this module has to check, neither of them a macro that
# survives the preprocessing of the headers into cffi definitions. The
# summary's is asked of the struct rather than written down, so that a
# libsecp256k1 that changes it changes this too; the label's is the 33
# bytes of a compressed point, which is its serialization and not the 68
# of the object holding it
SUMMARY_SIZE = ffi.sizeof("secp256k1_silentpayments_prevouts_summary")
LABEL_SIZE = 33

# the buffer `serialize_label` writes into, resolved here rather than at
# every call: `ffi.new` of an f-string formats it and leaves cffi to
# hash the result, where `ffi.typeof` of the same string, evaluated
# once, costs what a literal cdecl does and still states the width once.
# 0.2023 microseconds against 0.2621 on this serialization -- one
# session with every other figure of this change, which CHANGELOG.md
# names. `xonly.py` says the rest, the reason a literal cdecl is left
# alone included
_LABEL_BUFFER_TYPE = ffi.typeof(f"char[{LABEL_SIZE}]")


def _create_outputs_(
    recipients: Sequence[tuple[CData, CData]],
    outpoint_smallest36: BytesLike,
    taproot_prvkeys: Sequence[BytesLike | int] = (),
    prvkeys: Sequence[BytesLike | int] = (),
) -> list[CData]:
    """Create the taproot outputs paying already-parsed recipient keys.

    The private half of `create_outputs`, in both directions: it takes
    the parsed scan and spend keys and answers the parsed outputs. See
    the package docstring for what the two underscores mean throughout.
    A sender paying the same recipient in transaction after transaction
    parses that address once, where the public half is two field square
    roots per output.

    The private keys are not part of that trade and stay octets: they are
    consumed as scalars, the keypair a taproot input needs is built and
    wiped inside this call, and handing that lifetime to a caller would
    be a secret in memory nothing here could take back.

    Args:
        recipients: the addresses to pay, each a pair of the recipient's
            already-parsed scan and spend public keys. At least one is
            required.
        outpoint_smallest36: the 36-byte serialization of the
            lexicographically smallest outpoint of *all* the transaction
            inputs, eligible or not.
        taproot_prvkeys: the private keys of the taproot inputs, 32
            bytes or an int below 2**256 each.
        prvkeys: the private keys of the other eligible inputs.

    Returns:
        The libsecp256k1 x-only public key object of one taproot output
        per recipient, in the order the recipients were given.

    Raises:
        ValueError: if no recipient or no private key is given, if the
            outpoint is not 36 bytes, if any private key is not 32 bytes,
            does not fit in them, or is not in [1, n-1], if libsecp256k1
            refuses the set, or if any object is not a public key it will
            read, those last two being one message here --
            `context.check` is what tells them apart.
    """
    if not recipients:
        raise ValueError("at least one recipient is required")
    if not taproot_prvkeys and not prvkeys:
        raise ValueError("at least one private key is required")
    outpoint_smallest36 = octets(outpoint_smallest36, "smallest outpoint", 36)

    recipient_objs = [
        _recipient(scan_pubkey, spend_pubkey, index)
        for index, (scan_pubkey, spend_pubkey) in enumerate(recipients)
    ]
    outputs = [ffi.new("secp256k1_xonly_pubkey *") for _ in recipient_objs]

    # the two key lists are built inside the try, not before it: each
    # element carries a private key and the next one can raise, so what
    # wipes them has to already be in force while they are being made
    keypairs: list[CData] = []
    seckeys: list[CData] = []
    try:
        keypairs.extend(keypair(prvkey) for prvkey in taproot_prvkeys)
        seckeys.extend(
            ffi.new("unsigned char[32]", scalar(prvkey, "private key"))
            for prvkey in prvkeys
        )
        created = lib.secp256k1_silentpayments_sender_create_outputs(
            ctx,
            array("secp256k1_xonly_pubkey *[]", outputs),
            array("secp256k1_silentpayments_recipient *[]", recipient_objs),
            len(recipient_objs),
            outpoint_smallest36,
            array("secp256k1_keypair *[]", keypairs),
            len(keypairs),
            array("unsigned char *[]", seckeys),
            len(seckeys),
        )
    finally:
        for buffer in (*keypairs, *seckeys):
            wipe(buffer)

    if not created:
        raise ValueError("silent payment output creation failed")
    return outputs


def create_outputs(
    recipients_bytes: Sequence[tuple[BytesLike, BytesLike]],
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
        recipients_bytes: the addresses to pay, each a pair of the
            recipient's scan and spend public keys, 33 or 65 bytes each.
            The same address may appear more than once, which pays it
            that many outputs. At least one is required.
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
        >>> from btclib_secp256k1 import keys, silentpayments
        >>> scan_pubkey = keys.pubkey_from_prvkey(1)
        >>> spend_pubkey = keys.pubkey_from_prvkey(2)
        >>> outputs = silentpayments.create_outputs(
        ...     [(scan_pubkey, spend_pubkey)], bytes(36), prvkeys=[3]
        ... )
        >>> len(outputs), len(outputs[0])
        (1, 32)
    """
    recipients = [
        (
            keys.parse(scan_pubkey_bytes, "scan public key"),
            keys.parse(spend_pubkey_bytes, "spend public key"),
        )
        for scan_pubkey_bytes, spend_pubkey_bytes in recipients_bytes
    ]
    return [
        xonly.serialize(output)
        for output in _create_outputs_(
            recipients, outpoint_smallest36, taproot_prvkeys, prvkeys
        )
    ]


def _label_(scan_prvkey: BytesLike | int, m: int) -> tuple[CData, bytes]:
    """Create the m-th label of a scan key as a parsed label, and its tweak.

    The private half of `label`, and the one that answers with the label
    object rather than with its 33 bytes: see the package docstring for
    what the two underscores mean throughout. A label is a point, so
    parsing those 33 bytes back is a field square root -- which is what a
    recipient publishing a labeled address pays between `label` and
    `labeled_spend_pubkey`, and what this and `_labeled_spend_pubkey_`
    are for. The 33 bytes are still wanted, being what `scan_outputs` is
    keyed on: `serialize_label` is where they come from.

    Args:
        scan_prvkey: the recipient's scan private key, 32 bytes or an
            int below 2**256.
        m: which label, an int below 2**32. Zero is BIP352's change
            label.

    Returns:
        The libsecp256k1 label object, and the 32-byte tweak that spends
        what was paid to it.

    Raises:
        TypeError: if m is not an int.
        ValueError: if m is out of range, or if the scan key is not 32
            bytes, does not fit in them, or is not in [1, n-1].
    """
    scan_prvkey_bytes = scalar(scan_prvkey, "scan private key")
    # uint32_t: cffi would answer an out of range m with OverflowError,
    # which is not how this package reports an argument out of domain
    m = in_range(m, "label m", 2**32 - 1)

    label_obj = ffi.new("secp256k1_silentpayments_label *")
    tweak = ffi.new("char[32]")
    if not lib.secp256k1_silentpayments_recipient_label_create(
        ctx, label_obj, tweak, scan_prvkey_bytes, m
    ):
        # the hash landing outside [1, n-1] is the other way this fails,
        # and it has never been reached: it is negligible per evaluation
        raise ValueError("invalid scan private key")
    return label_obj, take(tweak)


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
        TypeError: if m is not an int.
        ValueError: if m is out of range, or if the scan key is not 32
            bytes, does not fit in them, or is not in [1, n-1].

    Example:
        >>> from btclib_secp256k1 import silentpayments
        >>> label, tweak = silentpayments.label(1, 0)
        >>> len(label), len(tweak)
        (33, 32)
    """
    label_obj, tweak = _label_(scan_prvkey, m)
    return serialize_label(label_obj), tweak


def _labeled_spend_pubkey_(spend_pubkey: CData, label_obj: CData) -> CData:
    """Add an already-parsed label to an already-parsed spend public key.

    The private half of `labeled_spend_pubkey`, taking both parsed
    objects and answering with a third: see the package docstring for
    what the two underscores mean throughout. A recipient publishing a
    labeled address holds both of them already -- the label from
    `_label_`, the spend key from `keys.parse` -- so this is the pair of
    C calls BIP352 asks for with no serialization between them, and
    `keys.serialize` is how what comes out becomes an address.

    Args:
        spend_pubkey: the recipient's already-parsed unlabeled spend
            public key, as `keys.parse` returns.
        label_obj: the parsed label, as `_label_` returns and as
            `parse_label` reads back.

    Returns:
        The libsecp256k1 public key object of the labeled spend key.

    Raises:
        ValueError: if the two sum to the point at infinity, which has no
            serialization and which a label BIP352 made cannot produce,
            or if either object is not one libsecp256k1 will read, those
            last two being one message here -- `context.check` is what
            tells them apart.
    """
    labeled = ffi.new("secp256k1_pubkey *")
    added = lib.secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
        ctx, labeled, spend_pubkey, label_obj
    )
    if not added:
        raise ValueError("invalid labeled spend public key")
    return labeled


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
        >>> from btclib_secp256k1 import keys, silentpayments
        >>> spend_pubkey = keys.pubkey_from_prvkey(2)
        >>> label, _ = silentpayments.label(1, 0)
        >>> len(silentpayments.labeled_spend_pubkey(spend_pubkey, label))
        33
    """
    return keys.serialize(
        _labeled_spend_pubkey_(
            keys.parse(spend_pubkey_bytes, "spend public key"),
            parse_label(label_bytes),
        ),
        compressed,
    )


def _prevouts_summary_(
    outpoint_smallest36: BytesLike,
    taproot_pubkeys: Sequence[CData] = (),
    pubkeys: Sequence[CData] = (),
) -> CData:
    """Summarize already-parsed input keys, as the summary object.

    The private half of `prevouts_summary`, and the one that answers with
    the object rather than with the octets of it: see the package
    docstring for what the two underscores mean throughout. What it saves
    is a round trip of the summary itself -- `_scan_outputs_` takes this
    object, where the public halves write those octets out of one struct
    and back into another -- and, for a caller holding the input keys
    parsed, their parse.

    Args:
        outpoint_smallest36: the 36-byte serialization of the
            lexicographically smallest outpoint of all the transaction
            inputs, eligible or not.
        taproot_pubkeys: the already-parsed x-only public keys of the
            taproot inputs, as `xonly.parse` returns.
        pubkeys: the already-parsed public keys of the other eligible
            inputs, as `keys.parse` returns.

    Returns:
        The libsecp256k1 summary object.

    Raises:
        ValueError: if no public key is given, if the outpoint is not 36
            bytes, if the inputs sum to the point at infinity, which is
            BIP352's "not a Silent Payments transaction" and which the
            recipient skips, or if any object is not a key libsecp256k1
            will read, those last two being one message here --
            `context.check` is what tells them apart.
    """
    if not taproot_pubkeys and not pubkeys:
        raise ValueError("at least one public key is required")
    outpoint_smallest36 = octets(outpoint_smallest36, "smallest outpoint", 36)

    summary = ffi.new("secp256k1_silentpayments_prevouts_summary *")
    summarized = lib.secp256k1_silentpayments_recipient_prevouts_summary_create(
        ctx,
        summary,
        outpoint_smallest36,
        array("secp256k1_xonly_pubkey *[]", taproot_pubkeys),
        len(taproot_pubkeys),
        array("secp256k1_pubkey *[]", pubkeys),
        len(pubkeys),
    )
    if not summarized:
        raise ValueError("not a silent payments transaction")
    return summary


def prevouts_summary(
    outpoint_smallest36: BytesLike,
    taproot_pubkeys_bytes: Sequence[BytesLike] = (),
    pubkeys_bytes: Sequence[BytesLike] = (),
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
        taproot_pubkeys_bytes: the x-only public keys of the taproot
            inputs, 32, 33 or 65 bytes each: an x names the even-y
            point whichever way it arrives, for which see `xonly.parse`.
        pubkeys_bytes: the public keys of the other eligible inputs, 33
            or 65 bytes each.

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
        >>> from btclib_secp256k1 import keys, silentpayments
        >>> summary = silentpayments.prevouts_summary(
        ...     bytes(36), pubkeys_bytes=[keys.pubkey_from_prvkey(3)]
        ... )
        >>> len(summary) == silentpayments.SUMMARY_SIZE
        True
    """
    summary = _prevouts_summary_(
        outpoint_smallest36,
        [
            xonly.parse(pubkey_bytes, "taproot public key")
            for pubkey_bytes in taproot_pubkeys_bytes
        ],
        [keys.parse(pubkey_bytes) for pubkey_bytes in pubkeys_bytes],
    )
    return bytes(ffi.buffer(summary))


def _scan_outputs_(
    tx_outputs: Sequence[CData],
    scan_prvkey: BytesLike | int,
    summary: CData,
    spend_pubkey: CData,
    labels: Mapping[bytes, BytesLike] | None = None,
) -> list[tuple[bytes, bytes, bytes | None]]:
    """Find the outputs paying an already-parsed Silent Payments address.

    The private half of `scan_outputs`: see the package docstring for
    what the two underscores mean throughout. A wallet scanning every
    transaction of a block parses its own spend key once here, where the
    public half parses it once per transaction, and takes the summary
    `_prevouts_summary_` built rather than octets to be written back into
    a struct.

    What it answers is octets even so: an output's tweak is a secret this
    call takes back out of libsecp256k1's memory before returning, and
    its x-only key is 32 bytes a caller compares rather than computes
    with.

    Args:
        tx_outputs: the already-parsed x-only public keys of the
            transaction's taproot outputs, in vout order, as
            `xonly.parse` returns. At least one is required.
        scan_prvkey: the recipient's scan private key, 32 bytes or an
            int below 2**256.
        summary: the summary of the transaction's inputs, as
            `_prevouts_summary_` returns.
        spend_pubkey: the recipient's already-parsed unlabeled spend
            public key, as `keys.parse` returns.
        labels: the recipient's label cache, mapping each 33-byte label
            to its 32-byte tweak, or None where no labeled address was
            published.

    Returns:
        One triple per output found, in vout order: its 32-byte x-only
        public key, the 32-byte tweak to add to the spend private key to
        spend it, and the 33-byte label it was found with, or None where
        it was paid to the unlabeled address.

    Raises:
        ValueError: if no output is given, if the scan key is not 32
            bytes, does not fit in them, or is not in [1, n-1], if a
            label or a label tweak is the wrong length, if libsecp256k1
            refuses the scan, or if any object is not one it will read,
            those last two being one message here -- `context.check` is
            what tells them apart.
    """
    if not tx_outputs:
        raise ValueError("at least one transaction output is required")
    scan_prvkey_bytes = scalar(scan_prvkey, "scan private key")

    # the found outputs array is as long as the outputs one, as the
    # header requires, and libsecp256k1 says through n_found how much of
    # it it wrote
    found_objs = [
        ffi.new("secp256k1_silentpayments_found_output *") for _ in tx_outputs
    ]
    n_found = ffi.new("uint32_t *")

    # the cache is filled inside the try, not built before it: every
    # entry carries a tweak and the next one can raise, so what wipes them
    # has to already be in force while they are being made -- create_outputs
    # builds its two key lists the same way and for the same reason. A
    # `dict` filled entry by entry is what makes that reachable, where a
    # comprehension would drop the ones already made along with the
    # exception
    cache: dict[bytes, CData] = {}
    # a NULL lookup is how libsecp256k1 is told no label is in play, and
    # it is not the same as one that never matches: with it the scan skips
    # the label branch altogether. What decides it is `labels`, an empty
    # mapping being a cache with nothing in it rather than the absence of
    # one; the callback is held in a local because it has to outlive the
    # call it is passed to
    lookup = ffi.NULL
    try:
        if labels is not None:
            _fill_label_cache(labels, cache)
            lookup = ffi.callback(
                "secp256k1_silentpayments_label_lookup", _lookup(cache)
            )
        scanned = lib.secp256k1_silentpayments_recipient_scan_outputs(
            ctx,
            array("secp256k1_silentpayments_found_output *[]", found_objs),
            n_found,
            array("secp256k1_xonly_pubkey *[]", tx_outputs),
            len(tx_outputs),
            scan_prvkey_bytes,
            summary,
            spend_pubkey,
            lookup,
            ffi.NULL,
        )
        if not scanned:
            raise ValueError("silent payment scanning failed")
        return [_found_output(found) for found in found_objs[: n_found[0]]]
    finally:
        # every found output carries the tweak that spends it, and the
        # cache the tweaks of the labels: both are secrets in memory this
        # package owns, and so both are taken back
        for buffer in (*found_objs, *cache.values()):
            wipe(buffer)


def scan_outputs(
    tx_outputs_bytes: Sequence[BytesLike],
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
        tx_outputs_bytes: the 32-byte x-only public keys of the
            transaction's taproot outputs, in vout order. At least one is
            required.
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
        >>> from btclib_secp256k1 import keys, silentpayments
        >>> scan_pubkey = keys.pubkey_from_prvkey(1)
        >>> spend_pubkey = keys.pubkey_from_prvkey(2)
        >>> outputs = silentpayments.create_outputs(
        ...     [(scan_pubkey, spend_pubkey)], bytes(36), prvkeys=[3]
        ... )
        >>> summary = silentpayments.prevouts_summary(
        ...     bytes(36), pubkeys_bytes=[keys.pubkey_from_prvkey(3)]
        ... )
        >>> found = silentpayments.scan_outputs(
        ...     outputs, 1, summary, spend_pubkey
        ... )
        >>> [pubkey for pubkey, _tweak, _label in found] == outputs
        True
    """
    summary_bytes = octets(summary_bytes, "prevouts summary", SUMMARY_SIZE)
    # the summary is opaque both ways: what came out of prevouts_summary
    # is written straight back into a struct of the same size, there
    # being no parser for it and nothing here that reads it
    summary = ffi.new("secp256k1_silentpayments_prevouts_summary *")
    ffi.buffer(summary)[:] = summary_bytes

    return _scan_outputs_(
        [
            xonly.parse(pubkey_bytes, "transaction output")
            for pubkey_bytes in tx_outputs_bytes
        ],
        scan_prvkey,
        summary,
        keys.parse(spend_pubkey_bytes, "spend public key"),
        labels,
    )


def _fill_label_cache(
    labels: Mapping[bytes, BytesLike], cache: dict[bytes, CData]
) -> None:
    """Copy a label cache into the buffers the lookup will hand back.

    Every tweak is copied into memory this package owns before the scan
    starts, rather than inside the callback: the pointer returned from
    there has to stay valid until libsecp256k1 is done with it, and a
    buffer made on the way out would be owned by nothing.

    The dictionary is filled rather than returned, so that a tweak copied
    before a later entry is refused is one the caller can still wipe: see
    `_scan_outputs_`, which owns it and does.

    Args:
        labels: the caller's mapping of 33-byte labels to 32-byte tweaks.
        cache: the dictionary to fill, keyed on the same labels.

    Raises:
        TypeError: if a label or a tweak is not bytes.
        ValueError: if a label is not 33 bytes, or a tweak not 32.
    """
    for label_bytes, tweak_bytes in labels.items():
        cache[octets(label_bytes, "label", LABEL_SIZE)] = ffi.new(
            "unsigned char[32]", octets(tweak_bytes, "label tweak", 32)
        )


def _lookup(cache: dict[bytes, CData]) -> Callable[[CData, CData], CData]:
    """Build the label lookup libsecp256k1 calls back into.

    Args:
        cache: the labels of `_fill_label_cache`, keyed on their 33 bytes.

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
    pubkey = xonly.serialize(ffi.addressof(found, "output"))
    # `ffi.buffer` and not `ffi.unpack`, which every fixed-size read in
    # this package is: the field is an `unsigned char[32]` rather than a
    # `char[32]`, and unpacking one answers a list of 32 ints
    tweak = bytes(ffi.buffer(found.tweak))
    if not found.found_with_label:
        return pubkey, tweak, None
    return pubkey, tweak, serialize_label(ffi.addressof(found, "label"))


def _recipient(scan_pubkey: CData, spend_pubkey: CData, index: int) -> CData:
    """Build one recipient of `_create_outputs_`.

    Args:
        scan_pubkey: the recipient's already-parsed scan public key.
        spend_pubkey: the recipient's already-parsed spend public key,
            labeled or not -- which of the two it is the sender neither
            knows nor needs to.
        index: the position of this recipient among them, which is what
            libsecp256k1 orders the outputs it returns by.

    Returns:
        The libsecp256k1 recipient object.
    """
    recipient = ffi.new("secp256k1_silentpayments_recipient *")
    # assigning a struct to a struct field copies it, so the parsed keys
    # need not outlive this call
    recipient.scan_pubkey = scan_pubkey[0]
    recipient.spend_pubkey = spend_pubkey[0]
    recipient.index = index
    return recipient


def parse_label(label_bytes: BytesLike) -> CData:
    """Parse a 33-byte label into its internal representation.

    What `keys.parse` is to a public key, this is to a label, and for the
    same reason: those 33 bytes are a compressed point, so reading them
    back is a field square root. A recipient that keeps its labels as
    bytes -- the cache `scan_outputs` takes is exactly that -- parses one
    here and hands it to `_labeled_spend_pubkey_`, rather than through
    the public half which parses it again at every address.

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


def serialize_label(label_obj: CData) -> bytes:
    """Serialize a label libsecp256k1 produced.

    What `keys.serialize` is to a public key: the 33 bytes are what a
    recipient keys its label cache on, and what `label` answers with.

    Args:
        label_obj: the libsecp256k1 label object, as `_label_` returns.

    Returns:
        Its 33 bytes, which are the compressed point it is.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object -- one it
            cannot read -- or fails to serialize for any other reason,
            which a label it produced cannot make it do.
            `context.check` is what tells the two apart.
    """
    output = ffi.new(_LABEL_BUFFER_TYPE)
    serialized = lib.secp256k1_silentpayments_recipient_label_serialize(
        ctx, output, label_obj
    )
    if not serialized:
        raise RuntimeError("label serialization failed")
    # the length is the constant the buffer's type was built from, so the
    # two still cannot say different numbers
    return ffi.unpack(output, LABEL_SIZE)

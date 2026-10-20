"""Tests für die strikt begrenzte Bencode-Implementierung."""

from __future__ import annotations

import unittest

from bittorrent_beobachter.bencode import (
    BencodeDecodeError,
    BencodeEncodeError,
    BencodeLimits,
    bdecode,
    bencode,
)


class BencodeTests(unittest.TestCase):
    def test_encoder_is_canonical_and_round_trips(self) -> None:
        value = {b"z": 3, b"a": [b"x", -4], b"middle": {b"k": b"v"}}

        encoded = bencode(value)

        self.assertEqual(encoded, b"d1:al1:xi-4ee6:middled1:k1:ve1:zi3ee")
        self.assertEqual(bdecode(encoded), value)

    def test_decoder_rejects_noncanonical_and_malformed_values(self) -> None:
        malformed = (
            b"",
            b"i03e",
            b"i-0e",
            b"i+1e",
            b"3:ab",
            b"01:a",
            b"le",
            b"d1:bi1e1:ai2ee",
            b"d1:ai1e1:ai2ee",
            b"i1ee",
        )
        # The empty list is valid and is tested separately from malformed input.
        for payload in malformed:
            if payload == b"le":
                self.assertEqual(bdecode(payload), [])
                continue
            with self.subTest(payload=payload), self.assertRaises(BencodeDecodeError):
                bdecode(payload)

    def test_decoder_enforces_all_resource_limits(self) -> None:
        with self.assertRaises(BencodeDecodeError):
            bdecode(b"4:spam", limits=BencodeLimits(max_payload_bytes=5))
        with self.assertRaises(BencodeDecodeError):
            bdecode(b"4:spam", limits=BencodeLimits(max_string_length=3))
        with self.assertRaises(BencodeDecodeError):
            bdecode(b"llee", limits=BencodeLimits(max_depth=0))
        with self.assertRaises(BencodeDecodeError):
            bdecode(b"li1ei2ee", limits=BencodeLimits(max_items=2))
        with self.assertRaises(BencodeDecodeError):
            bdecode(b"i12345e", limits=BencodeLimits(max_integer_digits=4))

    def test_encoder_rejects_unsupported_and_cyclic_values(self) -> None:
        cyclic: list[object] = []
        cyclic.append(cyclic)

        with self.assertRaises(BencodeEncodeError):
            bencode(True)
        with self.assertRaises(BencodeEncodeError):
            bencode("text")
        with self.assertRaises(BencodeEncodeError):
            bencode(cyclic)

    def test_encoder_enforces_output_limits(self) -> None:
        with self.assertRaises(BencodeEncodeError):
            bencode(b"spam", limits=BencodeLimits(max_payload_bytes=5))
        with self.assertRaises(BencodeEncodeError):
            bencode(b"spam", limits=BencodeLimits(max_string_length=3))


if __name__ == "__main__":
    unittest.main()

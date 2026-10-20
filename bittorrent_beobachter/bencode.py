"""Strikte, ressourcenbegrenzte Bencode-Kodierung und -Dekodierung."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class BencodeLimits:
    """Obergrenzen gegen übergroße oder tief verschachtelte Eingaben."""

    max_payload_bytes: int = 1_000_000
    max_depth: int = 32
    max_items: int = 100_000
    max_string_length: int = 1_000_000
    max_integer_digits: int = 128

    def __post_init__(self) -> None:
        for name in (
            "max_payload_bytes",
            "max_items",
            "max_string_length",
            "max_integer_digits",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} muss eine ganze Zahl sein.")
            if value < 1:
                raise ValueError(f"{name} muss mindestens 1 sein.")
        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int):
            raise TypeError("max_depth muss eine ganze Zahl sein.")
        if self.max_depth < 0:
            raise ValueError("max_depth darf nicht negativ sein.")


class BencodeError(ValueError):
    """Basisklasse für ungültige Bencode-Daten."""


class BencodeDecodeError(BencodeError):
    """Eine Eingabe ist kein kanonisch gültiges Bencode."""


class BencodeEncodeError(BencodeError):
    """Ein Python-Wert kann nicht sicher als Bencode kodiert werden."""


class _Decoder:
    def __init__(self, payload: bytes, limits: BencodeLimits) -> None:
        self.payload = payload
        self.limits = limits
        self.position = 0
        self.item_count = 0

    def decode(self) -> Any:
        if not self.payload:
            raise BencodeDecodeError("Leere Eingabe ist kein Bencode-Wert.")
        value = self._parse_value(depth=0)
        if self.position != len(self.payload):
            raise BencodeDecodeError("Unerwartete Daten hinter dem Bencode-Wert.")
        return value

    def _count_item(self) -> None:
        self.item_count += 1
        if self.item_count > self.limits.max_items:
            raise BencodeDecodeError("Bencode enthält zu viele Elemente.")

    def _parse_value(self, depth: int) -> Any:
        if depth > self.limits.max_depth:
            raise BencodeDecodeError("Bencode ist zu tief verschachtelt.")
        if self.position >= len(self.payload):
            raise BencodeDecodeError("Bencode endet mitten in einem Wert.")

        self._count_item()
        marker = self.payload[self.position]
        if marker == ord("i"):
            return self._parse_integer()
        if marker == ord("l"):
            return self._parse_list(depth)
        if marker == ord("d"):
            return self._parse_dictionary(depth)
        if ord("0") <= marker <= ord("9"):
            return self._parse_bytes()
        raise BencodeDecodeError(f"Ungültiges Bencode-Steuerzeichen an Position {self.position}.")

    def _parse_integer(self) -> int:
        end = self.payload.find(b"e", self.position + 1)
        if end < 0:
            raise BencodeDecodeError("Bencode-Ganzzahl hat kein Abschlusszeichen.")
        encoded = self.payload[self.position + 1 : end]
        if not encoded:
            raise BencodeDecodeError("Leere Bencode-Ganzzahl.")
        if len(encoded) > self.limits.max_integer_digits:
            raise BencodeDecodeError("Bencode-Ganzzahl ist zu lang.")

        digits = encoded[1:] if encoded.startswith(b"-") else encoded
        if not digits or not digits.isdigit():
            raise BencodeDecodeError("Bencode-Ganzzahl enthält ungültige Zeichen.")
        if encoded == b"-0":
            raise BencodeDecodeError("Negative Null ist nicht kanonisch.")
        if digits.startswith(b"0") and len(digits) > 1:
            raise BencodeDecodeError("Führende Nullen sind nicht kanonisch.")

        self.position = end + 1
        try:
            return int(encoded)
        except ValueError as exc:
            raise BencodeDecodeError("Bencode-Ganzzahl ist ungültig.") from exc

    def _parse_bytes(self) -> bytes:
        colon = self.payload.find(b":", self.position)
        if colon < 0:
            raise BencodeDecodeError("Bencode-Bytefolge hat keinen Doppelpunkt.")
        encoded_length = self.payload[self.position : colon]
        if not encoded_length or not encoded_length.isdigit():
            raise BencodeDecodeError("Ungültige Längenangabe einer Bencode-Bytefolge.")
        if encoded_length.startswith(b"0") and len(encoded_length) > 1:
            raise BencodeDecodeError("Führende Nullen in einer Länge sind nicht kanonisch.")
        if len(encoded_length) > 20:
            raise BencodeDecodeError("Längenangabe einer Bencode-Bytefolge ist zu lang.")

        length = int(encoded_length)
        if length > self.limits.max_string_length:
            raise BencodeDecodeError("Bencode-Bytefolge überschreitet die Größenbegrenzung.")
        start = colon + 1
        end = start + length
        if end > len(self.payload):
            raise BencodeDecodeError("Bencode-Bytefolge endet vor der angegebenen Länge.")
        self.position = end
        return self.payload[start:end]

    def _parse_list(self, depth: int) -> list[Any]:
        self.position += 1
        values: list[Any] = []
        while True:
            if self.position >= len(self.payload):
                raise BencodeDecodeError("Bencode-Liste hat kein Abschlusszeichen.")
            if self.payload[self.position] == ord("e"):
                self.position += 1
                return values
            values.append(self._parse_value(depth + 1))

    def _parse_dictionary(self, depth: int) -> dict[bytes, Any]:
        self.position += 1
        values: dict[bytes, Any] = {}
        previous_key: bytes | None = None
        while True:
            if self.position >= len(self.payload):
                raise BencodeDecodeError("Bencode-Wörterbuch hat kein Abschlusszeichen.")
            if self.payload[self.position] == ord("e"):
                self.position += 1
                return values
            if not ord("0") <= self.payload[self.position] <= ord("9"):
                raise BencodeDecodeError("Bencode-Wörterbuchschlüssel muss eine Bytefolge sein.")

            self._count_item()
            key = self._parse_bytes()
            if key in values:
                raise BencodeDecodeError("Doppelter Bencode-Wörterbuchschlüssel.")
            if previous_key is not None and key < previous_key:
                raise BencodeDecodeError(
                    "Bencode-Wörterbuchschlüssel sind nicht kanonisch sortiert."
                )
            previous_key = key
            values[key] = self._parse_value(depth + 1)


class _Encoder:
    def __init__(self, limits: BencodeLimits) -> None:
        self.limits = limits
        self.parts: list[bytes] = []
        self.payload_size = 0
        self.item_count = 0
        self.active_containers: set[int] = set()

    def encode(self, value: Any) -> bytes:
        self._encode_value(value, depth=0)
        return b"".join(self.parts)

    def _append(self, part: bytes) -> None:
        self.payload_size += len(part)
        if self.payload_size > self.limits.max_payload_bytes:
            raise BencodeEncodeError("Kodiertes Bencode überschreitet die Größenbegrenzung.")
        self.parts.append(part)

    def _count_item(self) -> None:
        self.item_count += 1
        if self.item_count > self.limits.max_items:
            raise BencodeEncodeError("Zu viele Elemente für eine Bencode-Kodierung.")

    def _encode_value(self, value: Any, depth: int) -> None:
        if depth > self.limits.max_depth:
            raise BencodeEncodeError("Wert ist zu tief verschachtelt.")
        self._count_item()

        if isinstance(value, bool):
            raise BencodeEncodeError("Boolesche Werte sind keine Bencode-Ganzzahlen.")
        if isinstance(value, int):
            encoded = str(value).encode("ascii")
            if len(encoded) > self.limits.max_integer_digits:
                raise BencodeEncodeError("Ganzzahl ist zu lang.")
            self._append(b"i" + encoded + b"e")
            return
        if isinstance(value, (bytes, bytearray, memoryview)):
            self._encode_bytes(bytes(value))
            return
        if isinstance(value, (list, tuple)):
            self._encode_list(value, depth)
            return
        if isinstance(value, Mapping):
            self._encode_dictionary(value, depth)
            return
        raise BencodeEncodeError(f"Nicht unterstützter Bencode-Typ: {type(value).__name__}.")

    def _encode_bytes(self, value: bytes) -> None:
        if len(value) > self.limits.max_string_length:
            raise BencodeEncodeError("Bytefolge überschreitet die Größenbegrenzung.")
        self._append(str(len(value)).encode("ascii") + b":" + value)

    def _enter_container(self, value: object) -> int:
        identity = id(value)
        if identity in self.active_containers:
            raise BencodeEncodeError("Zyklische Container können nicht kodiert werden.")
        self.active_containers.add(identity)
        return identity

    def _encode_list(self, values: list[Any] | tuple[Any, ...], depth: int) -> None:
        identity = self._enter_container(values)
        try:
            self._append(b"l")
            for value in values:
                self._encode_value(value, depth + 1)
            self._append(b"e")
        finally:
            self.active_containers.remove(identity)

    def _encode_dictionary(self, values: Mapping[Any, Any], depth: int) -> None:
        identity = self._enter_container(values)
        try:
            normalized: list[tuple[bytes, Any]] = []
            seen: set[bytes] = set()
            for key, value in values.items():
                self._count_item()
                if not isinstance(key, (bytes, bytearray, memoryview)):
                    raise BencodeEncodeError("Bencode-Wörterbuchschlüssel müssen Bytefolgen sein.")
                encoded_key = bytes(key)
                if encoded_key in seen:
                    raise BencodeEncodeError("Doppelter normalisierter Wörterbuchschlüssel.")
                seen.add(encoded_key)
                normalized.append((encoded_key, value))

            self._append(b"d")
            for key, value in sorted(normalized, key=lambda item: item[0]):
                self._encode_bytes(key)
                self._encode_value(value, depth + 1)
            self._append(b"e")
        finally:
            self.active_containers.remove(identity)


def bdecode(
    payload: bytes | bytearray | memoryview,
    *,
    limits: BencodeLimits | None = None,
) -> Any:
    """Dekodiert genau einen kanonischen, ressourcenbegrenzten Bencode-Wert."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload muss eine Bytefolge sein.")
    active_limits = limits or BencodeLimits()
    if len(payload) > active_limits.max_payload_bytes:
        raise BencodeDecodeError("Bencode-Eingabe überschreitet die Größenbegrenzung.")
    raw = bytes(payload)
    return _Decoder(raw, active_limits).decode()


def bencode(value: Any, *, limits: BencodeLimits | None = None) -> bytes:
    """Kodiert unterstützte Python-Werte deterministisch und kanonisch."""
    return _Encoder(limits or BencodeLimits()).encode(value)

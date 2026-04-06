"""Manual QPACK encoder for research purposes.

Provides low-level control over QPACK encoder stream instructions (RFC 9204),
allowing precise manipulation of the dynamic table. Each method generates
wire-format bytes AND updates an internal table tracker to stay in sync.

All generated instructions are strictly RFC-compliant — the goal is to test
how conformant servers handle valid-but-adversarially-sequenced instructions,
not to produce malformed data.
"""

from __future__ import annotations

from dataclasses import dataclass

from .qpack_static_table import STATIC_TABLE, STATIC_TABLE_SIZE

# ---------------------------------------------------------------------------
# 1A. QPACK Integer Encoding (RFC 9204 §4.1.1 / RFC 7541 §5.1)
# ---------------------------------------------------------------------------


def encode_integer(value: int, prefix_bits: int) -> bytes:
    """Encode a QPACK integer with the given prefix width.

    Returns the raw integer bytes. The caller is responsible for OR-ing any
    pattern/flag bits into the first byte.

    Args:
        value: Non-negative integer to encode.
        prefix_bits: Number of low bits in the first byte available for
            the integer (1–8).
    """
    if value < 0:
        raise ValueError(f"value must be non-negative, got {value}")
    if not 1 <= prefix_bits <= 8:
        raise ValueError(f"prefix_bits must be 1–8, got {prefix_bits}")

    max_prefix = (1 << prefix_bits) - 1

    if value < max_prefix:
        return bytes([value])

    buf = bytearray([max_prefix])
    value -= max_prefix
    while value >= 0x80:
        buf.append((value & 0x7F) | 0x80)
        value >>= 7
    buf.append(value)
    return bytes(buf)


def decode_integer(data: bytes, offset: int, prefix_bits: int) -> tuple[int, int]:
    """Decode a QPACK integer. Returns (value, bytes_consumed).

    Useful for testing and validation of encode_integer output.
    """
    if not 1 <= prefix_bits <= 8:
        raise ValueError(f"prefix_bits must be 1–8, got {prefix_bits}")
    if offset >= len(data):
        raise ValueError("offset beyond data length")

    max_prefix = (1 << prefix_bits) - 1
    value = data[offset] & max_prefix
    consumed = 1

    if value < max_prefix:
        return value, consumed

    shift = 0
    while True:
        if offset + consumed >= len(data):
            raise ValueError("truncated integer encoding")
        byte = data[offset + consumed]
        consumed += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break

    return value, consumed


# ---------------------------------------------------------------------------
# 1B. QPACK String Encoding (RFC 9204 §4.1.2)
# ---------------------------------------------------------------------------


def encode_string(value: bytes, use_huffman: bool = False) -> bytes:
    """Encode a length-prefixed string with a 7-bit length prefix.

    The high bit of the first byte is the Huffman flag. Huffman encoding
    is not implemented — if requested, raises NotImplementedError.
    """
    if use_huffman:
        raise NotImplementedError("Huffman encoding not yet supported")
    length_bytes = encode_integer(len(value), 7)
    # High bit clear = no Huffman (already 0 from encode_integer)
    return length_bytes + value


# ---------------------------------------------------------------------------
# 1C. Encoder Stream Instructions (RFC 9204 §4.3.1–4.3.4)
# ---------------------------------------------------------------------------


def set_dynamic_table_capacity(capacity: int) -> bytes:
    """Set Dynamic Table Capacity instruction (§4.3.1).

    Wire format: 0b001xxxxx with 5-bit prefix for capacity.
    """
    if capacity < 0:
        raise ValueError(f"capacity must be non-negative, got {capacity}")
    int_bytes = encode_integer(capacity, 5)
    buf = bytearray(int_bytes)
    buf[0] |= 0x20
    return bytes(buf)


def insert_with_name_ref(index: int, value: bytes, is_static: bool) -> bytes:
    """Insert With Name Reference instruction (§4.3.2).

    Wire format:
      - Static:  0b1_1_xxxxxx  (high bit=1, S=1, 6-bit index)
      - Dynamic: 0b1_0_xxxxxx  (high bit=1, S=0, 6-bit index)
    Followed by the value as an encoded string.
    """
    if index < 0:
        raise ValueError(f"index must be non-negative, got {index}")
    int_bytes = encode_integer(index, 6)
    buf = bytearray(int_bytes)
    buf[0] |= 0x80  # high bit = 1 (instruction type)
    if is_static:
        buf[0] |= 0x40  # S bit = 1
    return bytes(buf) + encode_string(value)


def insert_with_literal_name(name: bytes, value: bytes) -> bytes:
    """Insert With Literal Name instruction (§4.3.3).

    Wire format: 0b01_xxxxxx with 5-bit prefix for name length,
    followed by the name string, then the value string.

    Note: The high 2 bits are 01, and the name uses a 5-bit prefix
    for its length, with bit 5 being the Huffman flag for the name.
    """
    name_str = encode_string(name)
    # The instruction opcode is 0b01xxxxxx. The name string's first byte
    # uses a 5-bit length prefix. We need to shift the opcode into bits 6-7.
    buf = bytearray(name_str)
    buf[0] |= 0x40  # bit 6 = 1, bit 7 = 0  → 0b01_H_xxxxx
    return bytes(buf) + encode_string(value)


def duplicate(index: int) -> bytes:
    """Duplicate instruction (§4.3.4).

    Wire format: 0b000_xxxxx with 5-bit prefix for relative index.
    """
    if index < 0:
        raise ValueError(f"index must be non-negative, got {index}")
    int_bytes = encode_integer(index, 5)
    # High 3 bits are 000, which is already the case from encode_integer
    return bytes(int_bytes)


# ---------------------------------------------------------------------------
# 1C-2. Decoder Stream Instructions (RFC 9204 §4.4)
# ---------------------------------------------------------------------------


def parse_decoder_stream(data: bytes) -> list[tuple[str, int]]:
    """Parse QPACK decoder stream bytes into a list of instructions.

    Returns a list of (instruction_type, value) tuples:
      - ("insert_count_increment", increment)
      - ("section_ack", stream_id)
      - ("stream_cancellation", stream_id)
    """
    instructions: list[tuple[str, int]] = []
    offset = 0
    while offset < len(data):
        byte = data[offset]
        if byte & 0x80:
            # Section Acknowledgment: 1xxxxxxx, 7-bit prefix
            value, consumed = decode_integer(data, offset, 7)
            instructions.append(("section_ack", value))
        elif byte & 0x40:
            # Stream Cancellation: 01xxxxxx, 6-bit prefix
            value, consumed = decode_integer(data, offset, 6)
            instructions.append(("stream_cancellation", value))
        else:
            # Insert Count Increment: 00xxxxxx, 6-bit prefix
            value, consumed = decode_integer(data, offset, 6)
            instructions.append(("insert_count_increment", value))
        offset += consumed
    return instructions


def print_decoder_log(decoder_log: list[bytes]) -> None:
    """Parse and print decoder stream ack log in human-readable form."""
    all_data = b"".join(decoder_log)
    if not all_data:
        print("  Decoder ack log: (empty -- server has not sent an ack yet)")
        print("    Note: acks are only sent when the server decodes a header block")
        print("    that references dynamic table entries. In manual mode, our header")
        print("    blocks use only literals, so the server has no reason to ack.")
        return
    instructions = parse_decoder_stream(all_data)
    total_acked = sum(v for t, v in instructions if t == "insert_count_increment")
    print(f"  Decoder ack log: {len(instructions)} instructions, "
          f"server acknowledged {total_acked} insert(s)")
    for i, (itype, value) in enumerate(instructions):
        if itype == "insert_count_increment":
            print(f"    [{i}] Insert Count Increment: +{value}")
        elif itype == "section_ack":
            print(f"    [{i}] Section Acknowledgment: stream {value}")
        elif itype == "stream_cancellation":
            print(f"    [{i}] Stream Cancellation: stream {value}")


# ---------------------------------------------------------------------------
# 1D. Dynamic Table State Tracker
# ---------------------------------------------------------------------------

ENTRY_OVERHEAD = 32  # RFC 9204 §3.2.1: each entry costs name_len + value_len + 32


def print_dynamic_table(role: str, table: dict) -> None:
    """Print the QPACK dynamic table state as an ASCII table.

    Compatible with the dict returned by both ``pylsqpack.Decoder.get_dynamic_table()``
    and ``DynamicTableTracker.get_dynamic_table()`` — same interface as the
    ``print_dynamic_table`` in ``examples/http3_client.py``.
    """
    entries = table["entries"]
    max_cap = table["max_capacity"]
    cur_cap = table["current_capacity"]
    count = len(entries)

    print(f"\n=== QPACK Dynamic Table ({role.capitalize()}) ===")
    print("+-------+-----------------------------+-----------------------------+------+")
    print("| Index | Name                        | Value                       | Size |")
    print("+-------+-----------------------------+-----------------------------+------+")
    if not entries:
        print("|                              (empty)                                  |")
    else:
        for i, (name, value) in enumerate(entries):
            n = name.decode(errors="replace")
            v = value.decode(errors="replace")
            size = ENTRY_OVERHEAD + len(name) + len(value)
            print(f"| {i:>5} | {n:<27} | {v:<27} | {size:>4} |")
    print("+-------+-----------------------------+-----------------------------+------+")
    print(f"Capacity: {cur_cap}/{max_cap} bytes | Entries: {count}")
    print()


@dataclass
class DynamicTableEntry:
    name: bytes
    value: bytes

    @property
    def size(self) -> int:
        return len(self.name) + len(self.value) + ENTRY_OVERHEAD


class DynamicTableTracker:
    """Mirrors the QPACK dynamic table state.

    Tracks entries, capacity, and insert count to stay in sync with
    the instructions we generate.
    """

    def __init__(self) -> None:
        self.entries: list[DynamicTableEntry] = []  # index 0 = newest
        self.capacity: int = 0
        self.insert_count: int = 0  # absolute index counter

    def current_size(self) -> int:
        return sum(e.size for e in self.entries)

    def set_capacity(self, capacity: int) -> None:
        self.capacity = capacity
        self._evict()

    def insert(self, name: bytes, value: bytes) -> None:
        entry = DynamicTableEntry(name=name, value=value)
        if entry.size > self.capacity:
            raise ValueError(
                f"entry size {entry.size} exceeds table capacity {self.capacity}"
            )
        # Evict from the back until there's room
        while self.current_size() + entry.size > self.capacity:
            self.entries.pop()
        self.entries.insert(0, entry)
        self.insert_count += 1

    def duplicate(self, relative_index: int) -> None:
        if relative_index < 0 or relative_index >= len(self.entries):
            raise ValueError(
                f"relative index {relative_index} out of range "
                f"(table has {len(self.entries)} entries)"
            )
        source = self.entries[relative_index]
        self.insert(source.name, source.value)

    def get_dynamic_table(self) -> dict:
        """Return table state in the same dict format as pylsqpack.

        Returns ``{"max_capacity", "current_capacity", "entries"}`` where
        entries is a list of ``(name_bytes, value_bytes)`` tuples — the same
        shape returned by ``pylsqpack.Decoder.get_dynamic_table()``, so it
        can be passed directly to ``print_dynamic_table()``.
        """
        return {
            "max_capacity": self.capacity,
            "current_capacity": self.current_size(),
            "entries": [(e.name, e.value) for e in self.entries],
        }

    def _evict(self) -> None:
        while self.current_size() > self.capacity and self.entries:
            self.entries.pop()


# ---------------------------------------------------------------------------
# 1E. ManualQpackEncoder
# ---------------------------------------------------------------------------


class ManualQpackEncoder:
    """High-level manual QPACK encoder.

    Each method validates the operation, generates wire-format encoder stream
    bytes, and updates the internal table tracker to keep them in sync.
    """

    def __init__(self, max_table_capacity: int = 0) -> None:
        """
        Args:
            max_table_capacity: The server's SETTINGS_QPACK_MAX_TABLE_CAPACITY.
                set_capacity() will refuse to exceed this value.
        """
        self._table = DynamicTableTracker()
        self._max_table_capacity = max_table_capacity

    @property
    def table(self) -> DynamicTableTracker:
        return self._table

    @property
    def max_table_capacity(self) -> int:
        return self._max_table_capacity

    @max_table_capacity.setter
    def max_table_capacity(self, value: int) -> None:
        self._max_table_capacity = value

    def set_capacity(self, capacity: int) -> bytes:
        """Generate a Set Dynamic Table Capacity instruction.

        Validates capacity <= max_table_capacity, updates tracker.
        """
        if capacity < 0:
            raise ValueError(f"capacity must be non-negative, got {capacity}")
        if capacity > self._max_table_capacity:
            raise ValueError(
                f"capacity {capacity} exceeds server's max "
                f"table capacity {self._max_table_capacity}"
            )
        instruction = set_dynamic_table_capacity(capacity)
        self._table.set_capacity(capacity)
        return instruction

    def insert_name_ref(
        self, index: int, value: bytes, is_static: bool = True
    ) -> bytes:
        """Generate an Insert With Name Reference instruction.

        Validates the index exists in the referenced table, and that
        the resulting entry fits in the dynamic table.
        """
        if is_static:
            if index < 0 or index >= STATIC_TABLE_SIZE:
                raise ValueError(
                    f"static table index {index} out of range "
                    f"(0–{STATIC_TABLE_SIZE - 1})"
                )
            name = STATIC_TABLE[index][0]
        else:
            if index < 0 or index >= len(self._table.entries):
                raise ValueError(
                    f"dynamic table relative index {index} out of range "
                    f"(table has {len(self._table.entries)} entries)"
                )
            name = self._table.entries[index].name

        # Validate it will fit (insert() will raise if not)
        entry_size = len(name) + len(value) + ENTRY_OVERHEAD
        if entry_size > self._table.capacity:
            raise ValueError(
                f"entry size {entry_size} exceeds table capacity "
                f"{self._table.capacity}"
            )

        instruction = insert_with_name_ref(index, value, is_static)
        self._table.insert(name, value)
        return instruction

    def insert_literal(self, name: bytes, value: bytes) -> bytes:
        """Generate an Insert With Literal Name instruction.

        Validates the entry fits in the dynamic table.
        """
        entry_size = len(name) + len(value) + ENTRY_OVERHEAD
        if entry_size > self._table.capacity:
            raise ValueError(
                f"entry size {entry_size} exceeds table capacity "
                f"{self._table.capacity}"
            )

        instruction = insert_with_literal_name(name, value)
        self._table.insert(name, value)
        return instruction

    def duplicate(self, relative_index: int) -> bytes:
        """Generate a Duplicate instruction.

        Validates the relative index refers to an existing entry.
        """
        if relative_index < 0 or relative_index >= len(self._table.entries):
            raise ValueError(
                f"relative index {relative_index} out of range "
                f"(table has {len(self._table.entries)} entries)"
            )

        instruction = duplicate(relative_index)
        self._table.duplicate(relative_index)
        return instruction

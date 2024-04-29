#!/usr/bin/env python3
# Copyright 2024 0x4448
# SPDX-License-Identifier: MIT

import argparse
import sys

from binascii import hexlify
from dataclasses import dataclass
from pathlib import Path


class Keepass2HashcatException(Exception):
    pass


@dataclass
class KeepassDatabase:
    compression: int
    seed: str
    transform_seed: str
    rounds: int
    nonce: str
    expected: str
    contents: str
    offset: int

    def __init__(self):
        pass

    def __str__(self):
        return f"$keepass$*2*{self.rounds}*{self.offset}*{self.seed}*{self.transform_seed}*{self.nonce}*{self.expected}*{self.contents}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path, nargs="+")
    args = parser.parse_args()

    failed = 0

    for file in args.file:
        try:
            print(process(file))
        except Keepass2HashcatException as e:
            print(e)
            failed += 1

    sys.exit(failed)


def process(file: Path) -> KeepassDatabase:
    with open(file, "rb") as fp:
        data = fp.read()

    # bytes 0-3: KDBX signature (1)
    # bytes 4-7: KDBX signature (2)
    # bytes 8-11: format version
    if hexlify(data[0:8]) != b"03d9a29a67fb4bb5":
        raise Keepass2HashcatException(
            f"File does not start with KDBX signature: {file}"
        )
    if hexlify(data[8:12]) != b"01000300":
        raise Keepass2HashcatException(f"Only KDBX 3.1 files are supported: {file}")

    db = KeepassDatabase()

    # headers start at byte 12
    offset = 12

    while True:
        # field id: 1 byte
        field_id = int.from_bytes(data[offset : offset + 1])
        offset += 1

        # field size: 2 bytes
        field_size = int.from_bytes(data[offset : offset + 1])
        offset += 2

        # field value: field size bytes
        field_value: bytes = data[offset : offset + field_size]
        offset += field_size

        if field_id == 0:
            break

        if field_id == 2:
            if hexlify(field_value) != b"31c1f2e6bf714350be5805216afc5aff":
                raise Keepass2HashcatException("Only AES-256 is supported.")

        if field_id == 3:
            db.compression = int.from_bytes(field_value, "little")

        if field_id == 4:
            db.seed = hexlify(field_value).decode()

        if field_id == 5:
            db.transform_seed = hexlify(field_value).decode()

        if field_id == 6:
            db.rounds = int.from_bytes(field_value, "little")

        if field_id == 7:
            db.nonce = hexlify(field_value).decode()

        if field_id == 9:
            db.expected = hexlify(field_value).decode()

    db.contents = hexlify(data[offset : offset + 32]).decode()
    db.offset = offset

    return db


if __name__ == "__main__":
    main()

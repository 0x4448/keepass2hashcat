#!/usr/bin/env python3

import argparse
import itertools
import pathlib


parser = argparse.ArgumentParser()
parser.add_argument("wordlist", type=pathlib.Path)
parser.add_argument("-w", "--words", type=int, default=5)
parser.add_argument("-c", "--capitalize", action="store_true")
parser.add_argument("-n", "--number", action="store_true")
parser.add_argument("-s", "--separator", type=str, default="-")
args = parser.parse_args()

with open(args.wordlist) as fp:
    words = [line.strip() for line in fp.readlines() if line]

if args.capitalize:
    words = (word.title() for word in words)

for permutation in itertools.permutations(words, r=args.words):
    phrase = args.separator.join(permutation)

    if args.number:
        index = 0
        while True:
            index = phrase.find(args.separator, index)

            if index < 0:
                for i in range(10):
                    print(f"{phrase}{i}", flush=True)
                break

            for i in range(10):
                print(f"{phrase[0:index]}{i}{phrase[index:]}", flush=True)

            index += 1
    else:
        print(phrase, flush=True)

#!/usr/bin/env python3
"""
project1.py

Author: chen7790@umn.edu
Date: 09-23-2025

Recovers two plaintexts from one-time pad, in english.

Uses bigram frequencies from ftable2.csv for scoring, plus a score bonus for common English words.

Must run in a directory containing:
- ciphertexts.bin
- ftable2.csv

Outputs recovered_plaintexts.txt with the decrypted messages.
"""

import csv
import math
import random

ALPHABET = b" ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Common English words to help search
COMMON_WORDS = [
    "the", "and", "you", "that", "was", "this", "with", "for", "have", "not",
    "are", "but", "had", "they", "his", "from", "she", "which", "will", "one"
]

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def xor_bytes(b1, b2):
    return bytes([a ^ b for a, b in zip(b1, b2)])

# ftable2.csv to a dictionary for the probabilities
def load_ftable(path):
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for r in reader:
            rows.append(r)
    header = rows[0][1:]  # skip first empty cell containing header
    counts = {}
    for r in rows[1:]:
        a = r[0].strip()
        for i, v in enumerate(r[1:]):
            try:
                counts[(a, header[i])] = float(v)
            except:
                counts[(a, header[i])] = 0.0
    totals = {}
    for (a, b), v in counts.items():
        totals[a] = totals.get(a, 0.0) + v
    logp = {}
    floor = 1e-9  # set frequency floor to avoid math errors
    for (a, b), v in counts.items():
        tot = totals[a]
        prob = floor if tot <= 0 else max(v / tot, floor)
        logp[(a, b)] = math.log(prob)
    return logp

#map byte to char
def byte_to_char(b):
    if b == 32:
        return " "
    if 65 <= b <= 90:
        return chr(b)
    if 97 <= b <= 122:
        return chr(b - 32)  # Convert lowercase to uppercase to lookup the score
    return None

#score with bigram scores, penalty for not found
def score_bigram(b, logp):
    s = 0.0
    penalty = -100.0
    for i in range(len(b) - 1):
        a = byte_to_char(b[i])
        c = byte_to_char(b[i + 1])
        if a is None or c is None:
            s += penalty
        else:
            s += logp.get((a, c), math.log(1e-9))
    return s

# Bonus score for common English words
def word_bonus_score(text):
    text_lower = text.lower()
    bonus = 0
    for word in COMMON_WORDS:
        bonus += text_lower.count(word) * 10000  # 10,000 points per occurrence
    return bonus

def combined_score(candidate_bytes, logp):
    base_score = score_bigram(candidate_bytes, logp)
    try:
        as_text = candidate_bytes.decode('utf-8', errors='ignore')
    except:
        as_text = "" 
    bonus = word_bonus_score(as_text)
    return base_score + bonus

# Bulk algorithm with hill climbing and random restarts, XORing two ciphertexts and returning the best plaintexts
def hillclimb(X, logp, restarts=20, iterations=3000):
    k = len(X)
    best_pair, best_score = (b"", b""), -1e18  # Initialize low best score

    for r in range(restarts):
        p1 = bytearray([32] * k)
        cur_score = combined_score(p1, logp) + combined_score(xor_bytes(p1, X), logp)

        #random pick and propose mutation
        for it in range(iterations):
            i = random.randrange(k)
            old = p1[i]
            proposal = random.choice(ALPHABET)
            p1[i] = proposal

            new_score = combined_score(p1, logp) + combined_score(xor_bytes(p1, X), logp)
            delta = new_score - cur_score

            # Simulate the rest of the mutation 
            T = max(0.01, 1.0 - it / iterations)
            if delta >= 0 or random.random() < math.exp(delta / T):
                cur_score = new_score
                if new_score > best_score:
                    best_score = new_score
                    best_pair = (bytes(p1), xor_bytes(bytes(p1), X))
            else:
                p1[i] = old  # revert mutation if not accepted

    return best_pair, best_score

if __name__ == "__main__":
    # Prep pojrect environment by splitting ciphertexts.bin into two files
    with open('ciphertexts.bin', 'rb') as f:
        data = f.read()
    assert len(data) == 2048, "ciphertexts.bin must be 2048 bytes"
    with open('file1.bin', 'wb') as f1:
        f1.write(data[:1024])
    with open('file2.bin', 'wb') as f2:
        f2.write(data[1024:])

    c1_path = "file1.bin"
    c2_path = "file2.bin"
    ftable_path = "ftable2.csv"
    restarts = 20
    iterations = 3000

    c1 = read_file(c1_path)
    c2 = read_file(c2_path)
    if len(c1) != len(c2):
        print("Ciphertexts must be the same length")
        exit(1)

    X = xor_bytes(c1, c2)

    logp = load_ftable(ftable_path)

    (p1, p2), sc = hillclimb(X, logp, restarts=restarts, iterations=iterations)

    # Output recovered plaintexts to text file
    with open("recovered_plaintexts.txt", "w", encoding="utf-8") as f:
        f.write("--- Plaintext 1 ---\n")
        f.write(p1.decode("utf-8", errors="replace") + "\n\n")
        f.write("--- Plaintext 2 ---\n")
        f.write(p2.decode("utf-8", errors="replace") + "\n")

    print("Done. Best score:", sc)
    print("Recovered plaintexts written to recovered_plaintexts.txt")

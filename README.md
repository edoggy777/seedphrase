BIP-39 Compliant Seed Phrase Generator

This project provides a BIP-39 compliant seed phrase generator written
in C. It uses OpenSSL for cryptographic primitives and supports
generating mnemonics, deriving seeds, and working with custom entropy.

Features

-   Generate 12/15/18/21/24-word mnemonics from cryptographically secure
    entropy
-   Deterministic mnemonic generation from provided entropy (hex)
-   Derive 512-bit seed from mnemonic + optional passphrase using
    PBKDF2-HMAC-SHA512 (2048 rounds)
-   Uses official BIP-39 English wordlist (2048 words)

Requirements

-   C compiler (e.g., gcc)

-   OpenSSL development libraries (for libcrypto)

-   Official BIP-39 wordlist (2048 words):

        curl -O https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt

Build

    gcc -o seedphrase seedphrase.c -lcrypto

Usage

General Help

    ./seedphrase

Generate mnemonic from random entropy

    ./seedphrase generate english.txt 128

-   128 can be replaced with 160, 192, 224, 256 (bit strength).

Generate mnemonic from specific entropy

    ./seedphrase generate-from-entropy english.txt 00000000000000000000000000000000

Derive seed from mnemonic

    ./seedphrase seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" "TREZOR"

Example Output

    Entropy (hex): 8d8e72e8e4125a7c2ec067f16cfad6af
    Mnemonic: essay cradle banana curve ... (12 words)
    Seed (hex): c55257c360c07c72029aebc1b53c05ed0362ada3...

Notes

-   Wordlist: Must contain exactly 2048 words. Use the official
    english.txt linked above.
-   Use at your own risk

License

MIT

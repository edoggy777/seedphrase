#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_WORD_LEN 16
#define WORDLIST_SIZE 2048

char *wordlist[WORDLIST_SIZE];

// ---------------- Helper functions ----------------

// Load BIP-39 wordlist from file
int load_wordlist(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;

    char buffer[MAX_WORD_LEN];
    int i = 0;
    while (fgets(buffer, sizeof(buffer), f)) {
        size_t len = strlen(buffer);
        if (buffer[len-1] == '\n') buffer[len-1] = '\0';
        wordlist[i] = strdup(buffer);
        i++;
        if (i >= WORDLIST_SIZE) break;
    }
    fclose(f);
    return (i == WORDLIST_SIZE);
}

// Print bytes as hex
void print_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

// Convert entropy to mnemonic
char *entropy_to_mnemonic(const unsigned char *entropy, size_t entropy_len_bytes) {
    size_t ent_bits = entropy_len_bytes * 8;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(entropy, entropy_len_bytes, hash);

    size_t cs_len = ent_bits / 32;
    size_t total_bits = ent_bits + cs_len;
    size_t words = total_bits / 11;

    uint32_t *indices = calloc(words, sizeof(uint32_t));
    if (!indices) { fprintf(stderr, "Memory allocation failed\n"); exit(1); }

    for (size_t i = 0; i < words; i++) {
        uint32_t idx = 0;
        for (size_t b = 0; b < 11; b++) {
            size_t bit_pos = i * 11 + b;
            int bit;
            if (bit_pos < ent_bits) {
                size_t byte_index = bit_pos / 8;
                int bit_index = 7 - (bit_pos % 8);
                bit = (entropy[byte_index] >> bit_index) & 1;
            } else {
                size_t cs_bit = bit_pos - ent_bits;
                size_t byte_index = cs_bit / 8;
                int bit_index = 7 - (cs_bit % 8);
                bit = (hash[byte_index] >> bit_index) & 1;
            }
            idx = (idx << 1) | bit;
        }
        indices[i] = idx;
    }

    size_t out_sz = words * (MAX_WORD_LEN + 1);
    char *out = malloc(out_sz);
    if (!out) { fprintf(stderr, "Memory allocation failed\n"); exit(1); }
    out[0] = '\0';

    for (size_t i = 0; i < words; i++) {
        if (i) strcat(out, " ");
        strcat(out, wordlist[indices[i]]);
    }

    free(indices);
    return out;
}

// Derive 512-bit BIP-39 seed from mnemonic + optional passphrase
void mnemonic_to_seed(const char *mnemonic, const char *passphrase, unsigned char *seed) {
    char salt[256] = "mnemonic";
    if (passphrase && passphrase[0] != '\0') {
        strncat(salt, passphrase, sizeof(salt) - strlen(salt) - 1);
    }

    PKCS5_PBKDF2_HMAC(
        mnemonic,
        strlen(mnemonic),
        (unsigned char*)salt,
        strlen(salt),
        2048,          // iterations
        EVP_sha512(),
        64,            // 512-bit output
        seed
    );
}

// Print help
void print_help(const char *progname) {
    printf("BIP-39 Compliant Seed Phrase Generator\n");
    printf("=====================================\n");
    printf("Usage:\n");
    printf("  %s generate <wordlist> <strength>\n", progname);
    printf("      Generate mnemonic from random entropy.\n");
    printf("      <strength> must be 128,160,192,224,256 bits.\n");
    printf("  %s generate-from-entropy <wordlist> <hex-entropy>\n", progname);
    printf("      Generate mnemonic from provided hex entropy.\n");
    printf("  %s seed \"<mnemonic>\" [passphrase]\n", progname);
    printf("      Derive 512-bit seed from mnemonic + optional passphrase.\n");
    printf("  %s help\n", progname);
    printf("      Show this help message.\n");
    printf("Example:\n");
    printf("  %s generate english.txt 128\n", progname);
    printf("  %s generate-from-entropy english.txt 00000000000000000000000000000000\n", progname);
    printf("  %s seed \"abandon abandon abandon ... about\" \"TREZOR\"\n", progname);
}

// ---------------- Main ----------------
int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "help") == 0) {
        print_help(argv[0]);
        return 0;
    }

    // CLI: random entropy generation
    if (argc == 4 && strcmp(argv[1], "generate") == 0) {
        const char *wordlist_file = argv[2];
        int strength = atoi(argv[3]);
        if (!(strength == 128 || strength == 160 || strength == 192 ||
              strength == 224 || strength == 256)) {
            fprintf(stderr, "Invalid strength: %d\n", strength);
            return 1;
        }

        if (!load_wordlist(wordlist_file)) {
            fprintf(stderr, "Failed to load wordlist from %s\n", wordlist_file);
            return 1;
        }

        size_t ent_bytes = strength / 8;
        unsigned char *entropy = malloc(ent_bytes);
        if (!entropy) { fprintf(stderr, "Memory allocation failed\n"); return 1; }

        if (!RAND_bytes(entropy, ent_bytes)) {
            fprintf(stderr, "RAND_bytes failed\n"); free(entropy); return 1;
        }

        char *mnemonic = entropy_to_mnemonic(entropy, ent_bytes);

        printf("Entropy (hex): ");
        print_hex(entropy, ent_bytes);
        printf("Mnemonic: %s\n", mnemonic);

        free(entropy);
        free(mnemonic);
        return 0;
    }

    // CLI: generate from hex entropy
    if (argc == 4 && strcmp(argv[1], "generate-from-entropy") == 0) {
        const char *wordlist_file = argv[2];
        const char *hex_entropy = argv[3];

        if (!load_wordlist(wordlist_file)) {
            fprintf(stderr, "Failed to load wordlist from %s\n", wordlist_file);
            return 1;
        }

        size_t hex_len = strlen(hex_entropy);
        if (hex_len % 2 != 0) {
            fprintf(stderr, "Hex entropy must have even number of characters\n");
            return 1;
        }

        size_t ent_bytes = hex_len / 2;
        unsigned char *entropy = malloc(ent_bytes);
        if (!entropy) { fprintf(stderr, "Memory allocation failed\n"); return 1; }

        for (size_t i = 0; i < ent_bytes; i++) {
            unsigned int byte;
            if (sscanf(hex_entropy + 2*i, "%2x", &byte) != 1) {
                fprintf(stderr, "Invalid hex character in entropy\n");
                free(entropy);
                return 1;
            }
            entropy[i] = (unsigned char)byte;
        }

        char *mnemonic = entropy_to_mnemonic(entropy, ent_bytes);

        printf("Entropy (hex): %s\n", hex_entropy);
        printf("Mnemonic: %s\n", mnemonic);

        free(entropy);
        free(mnemonic);
        return 0;
    }

    // CLI: derive seed from mnemonic
    if (argc >= 3 && strcmp(argv[1], "seed") == 0) {
        const char *mnemonic = argv[2];
        const char *passphrase = (argc >= 4) ? argv[3] : "";

        unsigned char seed[64];
        mnemonic_to_seed(mnemonic, passphrase, seed);

        printf("Seed (hex): ");
        print_hex(seed, sizeof(seed));
        return 0;
    }

    printf("Invalid usage. Run '%s help' for instructions.\n", argv[0]);
    return 1;
}


#include "hashes.h"
//Taken from Source http://en.wikipedia.org/wiki/MurmurHash
uint32_t murmur3_32(const char *key, uint32_t len, uint32_t seed) {
    static const uint32_t c1 = 0xcc9e2d51;
    static const uint32_t c2 = 0x1b873593;
    static const uint32_t r1 = 15;
    static const uint32_t r2 = 13;
    static const uint32_t m = 5;
    static const uint32_t n = 0xe6546b64;

    uint32_t hash = seed;

    const int nblocks = len / 4;
    const uint32_t *blocks = (const uint32_t *) key;
    int i;
    for (i = 0; i < nblocks; i++) {
        uint32_t k = blocks[i];
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        hash ^= k;
        hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
    }

    const uint8_t *tail = (const uint8_t *) (key + nblocks * 4);
    uint32_t k1 = 0;

    switch (len & 3) {
    case 3:
        k1 ^= tail[2] << 16;
    case 2:
        k1 ^= tail[1] << 8;
    case 1:
        k1 ^= tail[0];

        k1 *= c1;
        k1 = (k1 << r1) | (k1 >> (32 - r1));
        k1 *= c2;
        hash ^= k1;
    }

    hash ^= len;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    return hash;
}

uint32_t murmur3_32_uint32(uint32_t value)
{
    //FIXME which seed should be used
    return murmur3_32((char*)&value, 4, 0xdeadbeef);
}

/* Problem: Popular hashes are distributed over 32 bit key space ranging from
 * 0 to 0xFFFFFF. However, often the bloom filters are smaller.
 * Therefore reduce the hash value to a the smaller key space.
 * FIXME Assume that the hash_values are equally distributed
 */
//FIXME Move to another file not directly related to murmur
uint32_t normalize32(uint32_t hash_value, uint32_t num_bits)
{
    uint32_t out;
    out = hash_value % num_bits;
    return out;
}

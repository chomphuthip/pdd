#ifndef PDD_H
#define PDD_H

#include<stdlib.h>
#include<string.h>

/* --- Vector --- */

#define pdd_vec_t(type) struct { size_t len, capacity, unit_size; type* buf; }

#define pdd_vec_typedef(type_name, element_type) typedef struct { \
    size_t len, capacity, unit_size; type* buf; } type_name

#define pdd_vec_init(vec) ((vec).len = 0, (vec).capacity = 0, (vec).buf = 0, \
        (vec).unit_size = sizeof(*(vec).buf))

#define pdd_vec_freeh(vec) free((vec).buf)

#define pdd_vec_at(vec, index) ((vec).buf[index])

#define pdd_vec_pop(vec) ((vec).buf[--(vec).len])

#define pdd_vec_len(vec) ((vec).len)

#define pdd_vec_capacity(vec) ((vec).capacity)

#define pdd_vec_resize(vec, new_capacity) \
    ((vec).capacity = (new_capacity), \
    (vec).buf = realloc((vec).buf, sizeof((vec).unit_size * (vec).capacity))

#define pdd_vec_push(vec, val) \
    do { \
        if ((vec).len == (vec).capacity) { \
            (vec).capacity = (vec).capacity ? (vec).capacity << 1 : 2; \
            (vec).buf = realloc((vec).buf, (vec).unit_size * (v).capacity) \
        } \
        (vec).buf[(vec).n++] = (val) \
    } while (0)

/* --- Stream --- */

typedef struct {
    char* buf;

    size_t capacity;
    size_t pos;
} pdd_stream_t;

pdd_stream_t* pdd_stream_new(size_t size) {
    pdd_stream_t* stream; 

    stream = malloc(sizeof(*stream));
    if(!stream) return 0;

    stream->buf = malloc(size);
    if(!stream->buf) {
        free(stream);
        return 0;
    }

    stream->capacity = size;
    stream->pos = 0;
    return stream;
}

size_t pdd_stream_write(pdd_stream_t* stream, char* src, size_t len) {
    size_t to_write;
    size_t remaining_space;

    remaining_space = stream->capacity - stream->pos;
    to_write = (len > remaining_space) ? remaining_space : len;

    memcpy(stream->buf + stream->pos, src, to_write);
    stream->pos += to_write;
    return to_write;
}

size_t pdd_stream_read(pdd_stream_t* stream, char* dest, size_t len) {
    size_t to_read;

    to_read = (len > stream->pos) ? stream->pos : len;
    memcpy(dest, stream->buf, to_read);
    stream->pos -= to_read;
    memmove(stream->buf, stream->buf + stream->pos, stream->pos);
    return to_read;
}

void pdd_stream_seek(pdd_stream_t* stream, int pos) {
    stream->pos = pos;
}

size_t pdd_stream_size(pdd_stream_t* stream) {
    return stream->capacity;
}

void pdd_stream_delete(pdd_stream_t* stream) {
    free(stream->buf);
    free(stream);
}

/* --- Hash Map --- */


/*
    Hash Map Implementation

    Hashing
        32bv are modulo'd
        str uses FNV-1a
        byte strings use FNV-1a with a fixed length

    Collision Handling
        Open Addressing with linear probing
        Resize upon 75% load
        Parallel array with bit flags
            first bit: if bucket is in use
            remainder: last 7 bits xored against hash
            

        chance for an fnv collision & having the same last 7 bits is 1 in 2^39

*/

struct _pdd_map_md_t {
    unsigned char in_use: 1;
    unsigned char discriminant: 7;
};

enum pdd_map_type {
    pdd_map_32bv = -1; // 32 bit value
    pdd_map_str = 0;
    // if using byte strings, specify a fixed byte length
};

// based on https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/ 
uint32_t _pdd_map_fast_range(uint32_t val, uint32_t max) {
    return ((uint64_t) val * (uint64_t) max) >> 32;
}

uint32_t _pdd_map_fnv(char* input, size_t len) {
    uint32_t res;

    res = 2166136261 //fnv offset basis
    for(int i = 0; i < len; i++) {
        res ^= input[i];
        res *= 16777619 //fnv prime
    }

    return res;
}

unsigned char _pdd_map_calc_discriminant(unsigned char first_byte, uint32_t hash) {
    return (hash ^ first_byte) & 0b1111111;
}

#define pdd_map_typedef(type_name, prefix, key_t, val_t, map_type) \
    typedef struct type_name { \
        size_t key_len; \
                    \
        size_t len; \
        size_t load; \
        val_t* values; \
        _pdd_map_md_t* metadata; \
    } type_name; \
                 \
    type_name* prefix##_new() { \
        type_name* new_map; \
        \
        new_map = calloc(1, sizeof(type_name)); \
        \
        if(map_type == -1) new_map->hash_func = pdd_map_32bv_hash; \
        else if(map_type == 0) new_map->hash_func = pdd_map_string_hash; \
        else { \
            new_map->hash_func = pdd_map_string_hash; \
            new_map->key_len = map_type; \
        } \
        \
        return new_map; \
    } \
    \
    uint32_t prefix##_hash(type_name* map, key_t key) { \
        switch(map_type) { \
            case pdd_map_32bv: \
                return key; \
            case pdd_map_str: \
                return _pdd_map_fnv(key, strlen(key)); \
            default: \
                return _pdd_map_fnv(key, map->key_len); \
        } \
    \
    uint32_t prefix##_naive_index(type_name* map, key_t key) { \
        return _pdd_map_fast_range(prefix##_hash(map, key)); \
    } \
    \
    /* fbof: first byte of key*/ \
    unsigned char prefix##_fbof(key_t key) { \
        return map_type == pdd_map_32bv ? (unsigned char)key : (unsigned char)(*key); \
    } \
    \
    val_t* prefix##_get_ref(type_name* map, key_t key) { \
        uint32_t index; \
        uint32_t metadata; \
        size_t dist_traveled; \
        unsigned char discriminant; \
        \
        index = prefix##_naive_index(map, key); \
        end = index; \
        \
        metadata = map->metadata[index]; \
        if(metadata.in_use == 0) return 0; \
        \
        discriminant = _pdd_map_calc_discriminant(prefix##_fbof(key), \
                _pdd_map_hash(map, key)); \
        \
        dist_traveled = 0; \
        while (metadata.discriminant != discriminant) { \
            if(index == map->len) index = 0; \
            if(dist_traveled == map->len) return 0; \
            metadata = map->metadata[++index]; \
            dist_traveled++; \
        } \
        \
        return &values[index]; \
    } \
    \
    val_t prefix##_get(type_name* map, key_t key) { \
        val_t empty; \
        val_t res; \
        \
        empty = {0}; \
        res = prefix##_get_ref(map, key); \
        return res == 0 ? empty : res; \
    } \
    \
    void prefix##_grow(type_name* map) { \
        size_t space_to_init; \
        size_t buf_to_init; \
        size_t metadata_to_init; \
        \
        space_to_init = map->len; \
        map->len = map->len * 2; \
        map->buf = realloc(map->buf, map->len * sizeof(val_t)); \
        map->metadata = realloc(map->metadata, map->len * sizeof(_pdd_map_md_t)); \
        \
        buf_to_init = space_to_init * sizeof(val_t); \
        metadata_to_init = space_to_init * sizeof(_pdd_map_md_t); \
        \
        memset(map->buf + buf_to_init, 0, buf_to_init); \
        memset(map->metadata + metadata_to_init, 0, metadata_to_init); \
    } \


#endif // PDD_H

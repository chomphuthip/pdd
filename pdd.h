#ifndef PDD_H
#define PDD_H

#include<stdlib.h>
#include<stdint.h>
#include<string.h>

/* --- Vector --- */

#define pdd_vec_t(type) struct { size_t len, capacity, unit_size; type* buf; }

#define pdd_vec_typedef(type_name, element_type) typedef struct { \
    size_t len, capacity, unit_size; element_type* buf; } type_name

#define pdd_vec_init(vec) ((vec).len = 0, (vec).capacity = 0, (vec).buf = 0, \
        (vec).unit_size = sizeof(*(vec).buf))

#define pdd_vec_destruct(vec) free((vec).buf)

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
            (vec).buf = realloc((vec).buf, (vec).unit_size * (vec).capacity); \
        } \
        (vec).buf[(vec).len++] = (val); \
    } while (0)

/* --- Stream --- */

typedef struct {
    char* buf;

    size_t capacity;
    size_t pos;
} pdd_stream_t;

int pdd_stream_init(pdd_stream_t* stream, size_t size) {
    stream->buf = malloc(size);
    if(!stream->buf) {
        free(stream);
        return 0;
    }

    stream->capacity = size;
    stream->pos = 0;
}

pdd_stream_t* pdd_stream_new(size_t size) {
    pdd_stream_t* stream; 

    stream = malloc(sizeof(*stream));
    if(!stream) return 0;

    pdd_stream_init(stream, size);
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
    memmove(stream->buf, stream->buf + to_read, 
            stream->capacity - to_read);
    stream->pos -= to_read;
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
        lit uses Wang
        str uses FNV-1a
        byte string uses FNV-1a

        you can write your own hash and comparison functions
            key_type##_hash
            key_type##_cmp

    Collision Handling
        Open Addressing with linear probing

    Architecture
        Array of buckets
            bucket has: flag, key, and value

        Hash to get naive index
        If isnt correct, linear probe key list

    Resizing
        allocate new bucket array
        hash each key and memmove bucket to new index in new array
*/


// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
uint32_t _pdd_map_fast_range(uint32_t val, uint32_t max) {
    return ((uint64_t) val * (uint64_t) max) >> 32;
}

uint32_t _pdd_map_fnv(char* input, size_t len) {
    uint32_t res;

    res = 2166136261; //fnv offset basis
    for(int i = 0; i < len; i++) {
        res ^= input[i];
        res *= 16777619; //fnv prime
    }

    return res;
}

uint32_t _pdd_map_wang(uint32_t input) {
    input += ~(input << 15);
    input ^=  (input >> 10);
    input +=  (input << 3);
    input ^=  (input >> 6);
    input += ~(input << 11);
    input ^=  (input >> 16);
    return input;
}

enum pdd_map_key_type {
    pdd_map_key_lit = -1,
    pdd_map_key_str = 0,
};

unsigned char pdd_map_cmp_lit_hash(uint32_t key) {
    return _pdd_map_wang(key);
}

unsigned char pdd_map_cmp_lit_cmp(uint32_t key_a, uint32_t key_b) {
    return key_a == key_b ? 1 : 0;
}

unsigned char pdd_map_cmp_str_hash(char* key) {
    return _pdd_map_fnv(key, strlen(key));
}

unsigned char pdd_map_cmp_str_cmp(char* key_a, char* key_b) {
    int cmp_1;
    int cmp_2;

    cmp_1 = (memcmp(key_a, key_b, 
                strlen(key_a)) == 0) ? 1 : 0; 
    cmp_2 = (memcmp(key_a, key_b,
                strlen(key_b)) == 0) ? 1 : 0; 
    return (cmp_1 && cmp_2) ? 1 : 0; 
}

#define pdd_map_cmp_byte_decl(len) \
    unsigned char pdd_map_cmp_byte_hash(char* key) { \
        return _pdd_map_fnv(key, len); \
    } \
    \
    unsigned char pdd_map_cmp_byte_cmp(char* key_a, char* key_b) { \
        return (memcmp(key_a, key_b,  \
                    len) == 0) ? 1 : 0;  \
    } \

#define pdd_map_typedef(type_name, prefix, key_t, val_t, key_type) \
    typedef struct type_name##_bucket_t { \
        char flags; \
        key_t key; \
        val_t val; \
    } type_name##_bucket_t; \
    \
    typedef struct type_name { \
        void (*delete_hook)(key_t, val_t); \
        \
        size_t len; \
        size_t entries; \
        type_name##_bucket_t* buckets; \
    } type_name; \
                 \
    int prefix##_init(type_name* map) { \
        map->entries = 0; \
        map->len = 16; \
        map->buckets = calloc(16, map->len * sizeof(type_name##_bucket_t)); \
        if(!map->buckets) return -1; \
        return 0; \
    } \
    type_name* prefix##_new() { \
        int res; \
        type_name* new_map; \
        \
        new_map = calloc(1, sizeof(*new_map)); \
        if(!new_map) return 0; \
        \
        res = prefix##_init(new_map); \
        if(res == -1) { \
            free(new_map); \
            return 0; \
        } \
        \
        return new_map; \
    } \
    \
    uint32_t prefix##_hash(key_t key) { \
        return key_type##_hash(key); \
    } \
    \
    uint32_t prefix##_cmp(key_t key_a, key_t key_b) { \
        return key_type##_cmp(key_a, key_b); \
    } \
    \
    uint32_t prefix##_naive_index(key_t key, uint32_t arr_len) { \
        return _pdd_map_fast_range(prefix##_hash(key), arr_len); \
    } \
    \
    uint32_t prefix##_new_index(type_name* map, key_t key) { \
        uint32_t index; \
        \
        index = prefix##_naive_index(key, map->len); \
        while(map->buckets[index].flags != 0) if(++index == map->len) index = 0; \
        \
        return index; \
    } \
    \
    int prefix##_cur_index(type_name* map, key_t key) { \
        uint32_t index; \
        uint32_t end; \
        \
        index = prefix##_naive_index(key, map->len); \
        end = _pdd_map_fast_range(index + map->len - 2, map->len); \
        while(map->buckets[index].flags != 0 && \
                !prefix##_cmp(key, map->buckets[index].key)) { \
                if(++index == map->len) index = 0; \
                if(index == end) return -1; \
        } \
        \
        return index; \
    } \
    \
    void prefix##_grow(type_name* map) { \
        uint32_t new_len; \
        uint32_t new_index; \
        type_name##_bucket_t* new_buckets; \
        \
        new_len = map->len * 2; \
        new_buckets = calloc(new_len, sizeof(*new_buckets)); \
        \
        for(int i = 0; i < map->len; i++) { \
            if(map->buckets[i].flags == 0) continue; \
            new_index = prefix##_new_index(map, map->buckets[i].key); \
            memmove(&new_buckets[new_index], &map->buckets[i], \
                    sizeof(type_name##_bucket_t)); \
        } \
        \
        free(map->buckets); \
        map->buckets = new_buckets; \
        map->len = new_len; \
    } \
    \
    void prefix##_delete(type_name* map, key_t key) { \
        uint32_t index; \
        \
        index = prefix##_cur_index(map, key); \
        if(index == -1) return; \
        \
        map->buckets[index].flags = 0; \
        map->delete_hook(map->buckets[index].key, \
                map->buckets[index].val); \
        map->entries--; \
    } \
    void prefix##_put(type_name* map, key_t key, val_t val) { \
        uint32_t index; \
        \
        if(map->entries + 1 > map->len * (3/4)) prefix##_grow(map); \
        \
        index = prefix##_new_index(map, key); \
        \
        map->buckets[index].flags = 1; \
        map->buckets[index].key = key; \
        map->buckets[index].val = val; \
        \
        map->entries++; \
    } \
    int prefix##_get(type_name* map, key_t key, val_t* dest) { \
        uint32_t index; \
        \
        index = prefix##_cur_index(map, key); \
        if(index == -1) return -1; \
        \
        memcpy(dest, &map->buckets[index].val, sizeof(val_t)); \
        return 0; \
    } \
    \
    val_t* prefix##_get_ptr(type_name* map, key_t key) { \
        uint32_t index; \
        \
        index = prefix##_cur_index(map, key); \
        if(index == -1) return 0; \
        return &map->buckets[index].val; \
    } \
    void prefix##_hook_del(type_name* map, void (*delete_hook)(key_t, val_t)) { \
        map->delete_hook = delete_hook; \
    } \

#endif // PDD_H

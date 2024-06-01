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
        byte strings use FNV-1a with a fixed length

    Collision Handling
        Open Addressing with linear probing

    Architecture
        Array of key pointers (string keys get pointer to pointers)
        Array of values 

        Hash to get naive index
        If isnt correct, linear probe key list
        If an index is not in use, its key pointer will be 0;

    Resizing
        allocate new index array
        hash each key and store in corresponding array
        alloc a new buffer
        memmcve each key to the new index
        memmove each value to the new index
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

uint32_t _pdd_map_wang(uintptr_t input) {
    input += ~(input << 15);
    input ^=  (input >> 10);
    input +=  (input << 3);
    input ^=  (input >> 6);
    input += ~(input << 11);
    input ^=  (input >> 16);
    return input;
}

enum pdd_map_key_len {
    pdd_map_type_lit = -1,
    pdd_map_type_str = 0,
    // otherwise, specifiy fixed key length of byte string 
};

#define pdd_map_typedef(type_name, prefix, key_t, val_t, key_len) \
    typedef struct type_name { \
        void (*delete_hook)(val_t val); \
        char* tombstones; \
        \
        size_t len; \
        size_t load; \
        key_t* keys; \
        val_t* vals; \
    } type_name; \
                 \
    type_name* prefix##_new() { \
        type_name* new_map; \
        \
        new_map = calloc(1, sizeof(type_name)); \
        new_map->load = 0; \
        new_map->delete_hook = 0; \
        \
        new_map->len = 16; \
        new_map->keys = calloc(new_map->len, sizeof(key_t*)); \
        new_map->vals = calloc(new_map->len, sizeof(val_t)); \
        new_map->tombstone = calloc(new_map->len, sizeof(char*)); \
        \
        memset(new_map->keys, 0, new_map->len * sizeof(key_t*)); \
        memset(new_map->vals, 0, new_map->len * sizeof(val_t)); \
        memset(new_map->tombestone, 0, new_map->len * sizeof(char*)); \
        \
        return new_map; \
    } \
    \
    uint32_t prefix##_hash(key_t key) { \
        switch(key_len) { \
            case pdd_map_type_lit: \
                return _pdd_map_wang((uintptr_t)key); \
            case pdd_map_type_str: \
                return _pdd_map_fnv(key, strlen(key)); \
            default: \
                return _pdd_map_fnv(key, key_len); \
        } \
    } \
    unsigned char prefix##_keycmp(type_name* map, key_t key_a, key_t key_b) { \
        char cmp_1; \
        char cmp_2; \
        \
        switch(key_len) { \
            case pdd_map_type_lit: \
                return (*key_a == *key_b) ? 1 : 0; \
            case pdd_map_type_str: \
                cmp_1 = (memcmp(key_a, key_b, strlen(key_a)) == 0) ? 1 : 0; \
                cmp_2 = (memcmp(key_a, key_b, strlen(key_b)) == 0) ? 1 : 0; \
                return (cmp_1 && cmp_2) ? 1 : 0; \
            default: \
                return (memcmp(key_a, key_b, key_len) == 0) ? 1 : 0; \
        } \
    }\
    \
    void prefix##_keysave(type_name* map, key_t key, uint32_t index) { \
        key_t* heap_key; \
        \
        switch(key_len) { \
            case pdd_map_type_lit: \
                map->tombstones[index] = 1; \
                map->keys[index] = key; \
                return; \
            case pdd_map_type_str: \
                map->tombstones[index] = 1; \
                map->keys[index] = strdup(key); \
                return; \
            default: \
                heap_key = malloc(key_len); \
                memcpy(heap_key, key, key_len) \
                map->keys[index] = heap_key; \
                return; \
        } \
    }\
    \
    uint32_t prefix##_naive_index(key_t key, uint32_t arr_len) { \
        return _pdd_map_fast_range(prefix##_hash(key), arr_len); \
    } \
    \
    void prefix##_grow(type_name* map) { \
        uint32_t new_len; \
        uint32_t index; \
        key_t** new_keys; \
        val_t* new_vals; \
        \
        /* TODO add error checking */ \
        new_len = map->len * 2; \
        new_keys = calloc(new_len, sizeof(key_t)); \
        new_vals = calloc(new_len, sizeof(val_t)); \
        new_tomb = calloc(new_len, sizeof(char)); \
        \
        memset(new_keys, 0, (new_len * sizeof(key_t*))); \
        memset(new_vals, 0, (new_len * sizeof(val_t))); \
        memset(new_tomb, 0, (new_len * sizeof(char))); \
        \
        for(int i = 0; i < new_len; i++) { \
            if(map->keys[i] == 0) continue; \
            \
            index = prefix##_naive_index(*map->keys[i], new_len); \
            while() { \
                if(++index == new_len) index = 0; \
            } \
            memmove(new_keys + i, map->keys[i], sizeof(key_t)); \
            memmove(new_vals + i, map->vals[i], sizeof(val_t)); \
            memmove(new_tomb + i, map->tomb[i], sizeof(char)); \
        } \
        free(map->keys); \
        free(map->vals); \
        free(map->tombstones); \
        \
        map->keys = new_keys; \
        map->vals = new_vals; \
        map->tombstones = new_tomb; \
        map->len = new_len; \
    } \
    \
    int prefix##_find_cur_index(type_name* map, key_t key) { \
        uint32_t index; \
        uint32_t dist_traveled; \
        \
        dist_traveled = 0; \
        index = prefix##_naive_index(key, map->len); \
        \
        while (!prefix##_keycmp(map, key, map->keys[index])) { \
            if(dist_traveled == map->len) return -1; \
            if(index == map->len) index = 0; \
            dist_traveled++; \
        } \
        \
        return index; \
    } \
    \
    int prefix##_find_new_index(type_name* map, key_t key) { \
        uint32_t index; \
        \
        index = prefix##_naive_index(key, map->len); \
        while(map->tombstones[index] != 0) { \
            if(++index == map->len) index = 0; \
        } \
        \
        return index; \
    } \
    \
    void prefix##_delete(type_name* map, key_t key) { \
        uint32_t index; \
        \
        index = prefix##_find_cur_index(map, key); \
        if(index == -1) return; \
        \
        map->delete_hook(map->vals[index]); \
        \
        map->tombstones[index] = 0; \
        free(map->keys[index]); \
        map->keys[index] = 0; \
        map->load--; \
    } \
    \
    int prefix##_get(type_name* map, key_t key, val_t* dest) { \
        uint32_t index; \
        \
        index = prefix##_find_cur_index(map, key); \
        if(index == -1) return -1; \
        \
        memcpy(dest, &map->vals[index], sizeof(val_t)); \
        return 0; \
    } \
    void prefix##_put(type_name* map, key_t key, val_t val) { \
        uint32_t index; \
        \
        map->load++; \
        if((map->load / map->len) * 100 >= 75) prefix##_grow(map); \
        \
        index = prefix##_find_new_index(map, key); \
        prefix##_keysave(map, key, index); \
        memcpy(&map->vals[index], val, sizeof(val_t)); \
    } \
    \
    void prefix##_hook_del(type_name* map, void (*delete_hook)(val_t)) { \
        map->delete_hook = delete_hook; \
    } \

#endif // PDD_H

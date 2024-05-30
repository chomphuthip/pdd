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
    (vec).buf = (*type)realloc((vec).buf, sizeof((vec).unit_size * (vec).capacity))

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
       32bv uses random bitshifting
       str uses FNV-1a
       byte strings use FNV-1a

    Collision Handling
        Open Addressing with linear probing
        Resize upon 75% load
        Parallel array with bit flags
            first bit: if bucket is in use
            bottom 31: fibonacci hash to verify correct key
            
*/

struct _pdd_map_flags {
    int in_use: 1;
    int hash: 31;
};

enum pdd_map_type {
    pdd_map_32bv = -1; // 32 bit value
    pdd_map_str = 0;
    // if using byte strings, specify a fixed byte length
};

uint32_t pdd_map_32bv_hash(uint32_t to_hash) {

}

#define pdd_map_typedef(type_name, prefix, key_t, val_t, map_type) \
    typedef struct type_name { \
        uint32_t (*hash_func)(*void to_hash); \
        size_t key_len; \
                        \
        uint32_t*  flags; \
        val_t* keys; \
    } type_name; \
                 \
    type_name* prefix##_new() { \
        type_name* new_map; \
                            \
        new_map = calloc(1, sizeof(type_name)); \
                                                \
        if(map_type == -1) new_map->hash_func = pdd_map_32bv_hash \
        else if(map_type == 0) new_map->hash_func = pdd_map_string_hash \
        else { \
            new_map->hash_func = pdd_map_string_hash; \
            new_map->key_len = map_type; \
        } \
        return new_map \
    } \
      \


#endif // PDD_H

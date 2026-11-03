// Snapmaker U1 spool tag: key derivation + field decode.
// Pure C, no Flipper dependencies, so test/test_snapmaker.c compiles it on the host.
// Layout and KDF follow Snapmaker/u1-klipper (GPL-3.0):
//   klippy/extras/fm175xx_reader.py  (_hkdf_create_key)
//   klippy/extras/filament_protocol.py (M1_PROTO_*_POS)
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// ---- SHA-256 / HMAC (the SDK does not export mbedtls to .fal plugins) ----
typedef struct {
    uint32_t state[8];
    uint64_t bit_len;
    uint8_t buf[64];
    size_t buf_len;
} SmSha256;

static inline uint32_t sm_rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sm_sha256_block(SmSha256* c, const uint8_t p[64]) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    uint32_t w[64];
    for(size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
    }
    for(size_t i = 16; i < 64; i++) {
        uint32_t s0 = sm_rotr(w[i - 15], 7) ^ sm_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sm_rotr(w[i - 2], 17) ^ sm_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];
    for(size_t i = 0; i < 64; i++) {
        uint32_t t1 = h + (sm_rotr(e, 6) ^ sm_rotr(e, 11) ^ sm_rotr(e, 25)) +
                      ((e & f) ^ (~e & g)) + k[i] + w[i];
        uint32_t t2 = (sm_rotr(a, 2) ^ sm_rotr(a, 13) ^ sm_rotr(a, 22)) +
                      ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sm_sha256_init(SmSha256* c) {
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->state, iv, sizeof(iv));
    c->bit_len = 0;
    c->buf_len = 0;
}

static void sm_sha256_update(SmSha256* c, const uint8_t* d, size_t n) {
    for(size_t i = 0; i < n; i++) {
        c->buf[c->buf_len++] = d[i];
        if(c->buf_len == 64) {
            sm_sha256_block(c, c->buf);
            c->bit_len += 512;
            c->buf_len = 0;
        }
    }
}

static void sm_sha256_final(SmSha256* c, uint8_t out[32]) {
    c->bit_len += c->buf_len * 8;
    c->buf[c->buf_len++] = 0x80;
    if(c->buf_len > 56) {
        memset(c->buf + c->buf_len, 0, 64 - c->buf_len);
        sm_sha256_block(c, c->buf);
        c->buf_len = 0;
    }
    memset(c->buf + c->buf_len, 0, 56 - c->buf_len);
    for(int i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(c->bit_len >> (56 - 8 * i));
    sm_sha256_block(c, c->buf);
    for(int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->state[i];
    }
}

// key_len must be <= 64 (true for every caller here: salts are 25/32 bytes, PRK is 32).
static void sm_hmac_sha256(
    const uint8_t* key, size_t key_len, const uint8_t* d, size_t n, uint8_t out[32]) {
    uint8_t pad[64], inner[32];
    SmSha256 c;
    memset(pad, 0x36, 64);
    for(size_t i = 0; i < key_len; i++) pad[i] ^= key[i];
    sm_sha256_init(&c);
    sm_sha256_update(&c, pad, 64);
    sm_sha256_update(&c, d, n);
    sm_sha256_final(&c, inner);
    memset(pad, 0x5c, 64);
    for(size_t i = 0; i < key_len; i++) pad[i] ^= key[i];
    sm_sha256_init(&c);
    sm_sha256_update(&c, pad, 64);
    sm_sha256_update(&c, inner, 32);
    sm_sha256_final(&c, out);
}

// ---- Key derivation ----
// HKDF-SHA256: PRK = HMAC(salt, uid[0..4]); key_X_N = HMAC(PRK, "key_X_N" || 0x01)[0..6].
// Key A and key B use different salts.
#define SM_SECTORS 16

static void sm_derive_keys(const uint8_t uid[4], uint8_t key_a[SM_SECTORS][6], uint8_t key_b[SM_SECTORS][6]) {
    static const char salt_a[] = "Snapmaker_qwertyuiop[,.;]";
    static const char salt_b[] = "Snapmaker_qwertyuiop[,.;]_1q2w3e";
    for(int kind = 0; kind < 2; kind++) {
        const char* salt = kind ? salt_b : salt_a;
        uint8_t prk[32], t[32];
        sm_hmac_sha256((const uint8_t*)salt, strlen(salt), uid, 4, prk);
        for(int s = 0; s < SM_SECTORS; s++) {
            uint8_t info[12];
            size_t n = 0;
            memcpy(info, "key_a_", 6);
            info[4] = kind ? 'b' : 'a';
            n = 6;
            if(s >= 10) info[n++] = '1';
            info[n++] = (uint8_t)('0' + s % 10);
            info[n++] = 0x01;
            sm_hmac_sha256(prk, 32, info, n, t);
            memcpy(kind ? key_b[s] : key_a[s], t, 6);
        }
    }
}

// ---- Field decode ----
// Blocks that hold every field below. Sector trailers (3,7,11) excluded.
static const uint8_t SM_REQUIRED_BLOCKS[] = {1, 2, 4, 5, 6, 8, 9, 10};
#define SM_REQUIRED_BLOCK_COUNT (sizeof(SM_REQUIRED_BLOCKS) / sizeof(SM_REQUIRED_BLOCKS[0]))

typedef struct {
    char vendor[17];
    char manufacturer[17];
    uint16_t version, main_type, sub_type, tray;
    uint8_t color_count, alpha, multi_mode;
    uint8_t rgb[5][3];
    uint32_t sku;
    uint16_t diameter_x100, weight_g, length_m;
    uint16_t dry_temp, dry_hours, hotend_max, hotend_min;
    uint16_t bed_type, bed_temp, first_layer_temp, other_layer_temp;
    char mf_date[9];
    uint16_t rsa_key_version;
} SmFilament;

static inline uint16_t sm_le16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static const char* sm_main_type_name(uint16_t v) {
    switch(v) {
    case 1: return "PLA"; case 2: return "PETG"; case 3: return "ABS"; case 4: return "TPU";
    case 5: return "PVA"; case 6: return "ASA"; case 9: return "PA"; case 10: return "PA-CF";
    case 11: return "PA-GF"; case 12: return "PC"; case 17: return "PETG-CF";
    case 20: return "PLA-CF"; case 22: return "PEBA"; case 23: return "TPE";
    default: return NULL;
    }
}

static const char* sm_sub_type_name(uint16_t v) {
    static const char* const names[] = {
        "", "Basic", "Matte", "SnapSpeed", "Silk", "Support", "HF", "95A", "95A HF",
        "90A", "85A", "Wood", "Translucent", "Full Spectrum", "Glow", "Rainbow", "Marble"};
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : NULL;
}

static void sm_copy_str(char* dst, const uint8_t* src, size_t n) {
    size_t i;
    for(i = 0; i < n && src[i] >= 0x20 && src[i] <= 0x7e; i++) dst[i] = (char)src[i];
    dst[i] = 0;
}

// `mem` is the 1 KB tag image (64 blocks x 16 bytes). Returns false when the
// data cannot be a Snapmaker spool (unknown material or bad colour count).
static bool sm_decode(const uint8_t* mem, SmFilament* f) {
    memset(f, 0, sizeof(*f));
    sm_copy_str(f->vendor, mem + 16, 16);
    sm_copy_str(f->manufacturer, mem + 32, 16);
    f->version = sm_le16(mem + 64);
    f->main_type = sm_le16(mem + 66);
    f->sub_type = sm_le16(mem + 68);
    f->tray = sm_le16(mem + 70);
    f->color_count = mem[72];
    f->alpha = (uint8_t)(0xFF - mem[73]); // stored inverted
    f->multi_mode = mem[74];
    memcpy(f->rgb, mem + 80, 15);
    f->sku = (uint32_t)mem[96] | ((uint32_t)mem[97] << 8) | ((uint32_t)mem[98] << 16) |
             ((uint32_t)mem[99] << 24);
    f->diameter_x100 = sm_le16(mem + 128);
    f->weight_g = sm_le16(mem + 130);
    f->length_m = sm_le16(mem + 132);
    f->dry_temp = sm_le16(mem + 144);
    f->dry_hours = sm_le16(mem + 146);
    f->hotend_max = sm_le16(mem + 148);
    f->hotend_min = sm_le16(mem + 150);
    f->bed_type = sm_le16(mem + 152);
    f->bed_temp = sm_le16(mem + 154);
    f->first_layer_temp = sm_le16(mem + 156);
    f->other_layer_temp = sm_le16(mem + 158);
    sm_copy_str(f->mf_date, mem + 160, 8);
    f->rsa_key_version = sm_le16(mem + 168);
    return sm_main_type_name(f->main_type) != NULL && f->color_count >= 1 &&
           f->color_count <= 5 && f->vendor[0] != 0;
}

// ---- OpenSpool export (U1 Extended firmware reads this from an NTAG215/216) ----
// Field set and value types follow U1 Extended's filament_protocol_ndef.py: numbers
// are parsed with int()/float(), so alpha is written as a decimal integer, not hex.
#define SM_JSON_MAX 320

static size_t sm_cat(char* out, size_t cap, size_t len, const char* s) {
    while(*s && len + 1 < cap) out[len++] = *s++;
    out[len] = 0;
    return len;
}

static size_t sm_cat_u(char* out, size_t cap, size_t len, uint32_t v) {
    char tmp[11];
    int i = 10;
    tmp[i] = 0;
    do {
        tmp[--i] = (char)('0' + v % 10);
        v /= 10;
    } while(v);
    return sm_cat(out, cap, len, tmp + i);
}

static size_t sm_cat_hex(char* out, size_t cap, size_t len, const uint8_t rgb[3]) {
    static const char d[] = "0123456789ABCDEF";
    char tmp[7] = {d[rgb[0] >> 4], d[rgb[0] & 15], d[rgb[1] >> 4], d[rgb[1] & 15],
                   d[rgb[2] >> 4], d[rgb[2] & 15], 0};
    return sm_cat(out, cap, len, tmp);
}

// Returns the JSON length. Zero-valued optional fields are left out.
static size_t sm_openspool_json(const SmFilament* f, char out[SM_JSON_MAX]) {
    size_t n = 0, cap = SM_JSON_MAX;
    out[0] = 0;
    n = sm_cat(out, cap, n, "{\"protocol\":\"openspool\",\"version\":\"1.0\",\"brand\":\"");
    n = sm_cat(out, cap, n, f->vendor[0] ? f->vendor : (f->manufacturer[0] ? f->manufacturer : "Snapmaker"));
    n = sm_cat(out, cap, n, "\",\"type\":\"");
    n = sm_cat(out, cap, n, sm_main_type_name(f->main_type));
    const char* sub = sm_sub_type_name(f->sub_type);
    if(sub && sub[0]) {
        n = sm_cat(out, cap, n, "\",\"subtype\":\"");
        n = sm_cat(out, cap, n, sub);
    }
    n = sm_cat(out, cap, n, "\",\"color_hex\":\"");
    n = sm_cat_hex(out, cap, n, f->rgb[0]);
    n = sm_cat(out, cap, n, "\"");
    if(f->color_count > 1) {
        n = sm_cat(out, cap, n, ",\"additional_color_hexes\":[");
        for(uint8_t i = 1; i < f->color_count && i < 5; i++) {
            n = sm_cat(out, cap, n, i > 1 ? ",\"" : "\"");
            n = sm_cat_hex(out, cap, n, f->rgb[i]);
            n = sm_cat(out, cap, n, "\"");
        }
        n = sm_cat(out, cap, n, "]");
    }
    if(f->alpha != 0xFF) n = sm_cat_u(out, cap, sm_cat(out, cap, n, ",\"alpha\":"), f->alpha);
    if(f->hotend_min) n = sm_cat_u(out, cap, sm_cat(out, cap, n, ",\"min_temp\":"), f->hotend_min);
    if(f->hotend_max) n = sm_cat_u(out, cap, sm_cat(out, cap, n, ",\"max_temp\":"), f->hotend_max);
    if(f->bed_temp) {
        n = sm_cat_u(out, cap, sm_cat(out, cap, n, ",\"bed_min_temp\":"), f->bed_temp);
        n = sm_cat_u(out, cap, sm_cat(out, cap, n, ",\"bed_max_temp\":"), f->bed_temp);
    }
    if(f->weight_g) n = sm_cat_u(out, cap, sm_cat(out, cap, n, ",\"weight\":"), f->weight_g);
    if(f->diameter_x100) {
        n = sm_cat_u(out, cap, sm_cat(out, cap, n, ",\"diameter\":"), f->diameter_x100 / 100);
        n = sm_cat(out, cap, n, f->diameter_x100 % 100 < 10 ? ".0" : ".");
        n = sm_cat_u(out, cap, n, f->diameter_x100 % 100);
    }
    return sm_cat(out, cap, n, "}");
}

// NTAG user memory image: TLV 0x03 wrapping one MIME record (application/json), then 0xFE.
// Returns bytes written, 0 if it does not fit.
static size_t sm_ndef_build(const char* json, size_t json_len, uint8_t* out, size_t cap) {
    static const char mime[] = "application/json";
    const size_t type_len = sizeof(mime) - 1;
    bool sr = json_len < 256;
    size_t rec_len = 1 + 1 + (sr ? 1 : 4) + type_len + json_len;
    size_t tlv_hdr = rec_len < 255 ? 2 : 4;
    if(tlv_hdr + rec_len + 1 > cap) return 0;
    size_t n = 0;
    out[n++] = 0x03;
    if(tlv_hdr == 2) {
        out[n++] = (uint8_t)rec_len;
    } else {
        out[n++] = 0xFF;
        out[n++] = (uint8_t)(rec_len >> 8);
        out[n++] = (uint8_t)rec_len;
    }
    out[n++] = (uint8_t)(0xC2 | (sr ? 0x10 : 0)); // MB | ME | (SR) | TNF=MIME
    out[n++] = (uint8_t)type_len;
    if(sr) {
        out[n++] = (uint8_t)json_len;
    } else {
        out[n++] = (uint8_t)(json_len >> 24);
        out[n++] = (uint8_t)(json_len >> 16);
        out[n++] = (uint8_t)(json_len >> 8);
        out[n++] = (uint8_t)json_len;
    }
    memcpy(out + n, mime, type_len);
    n += type_len;
    memcpy(out + n, json, json_len);
    n += json_len;
    out[n++] = 0xFE;
    return n;
}

// "OpenSpool_<brand>_<type>_<sub>_<RRGGBB>" with anything non-alphanumeric folded to '_'.
static void sm_openspool_name(const SmFilament* f, char* out, size_t cap) {
    char tmp[64];
    size_t n = 0;
    n = sm_cat(tmp, sizeof(tmp), n, "OpenSpool_");
    n = sm_cat(tmp, sizeof(tmp), n, f->vendor);
    n = sm_cat(tmp, sizeof(tmp), n, "_");
    n = sm_cat(tmp, sizeof(tmp), n, sm_main_type_name(f->main_type));
    const char* sub = sm_sub_type_name(f->sub_type);
    if(sub && sub[0]) {
        n = sm_cat(tmp, sizeof(tmp), n, "_");
        n = sm_cat(tmp, sizeof(tmp), n, sub);
    }
    n = sm_cat(tmp, sizeof(tmp), n, "_");
    n = sm_cat_hex(tmp, sizeof(tmp), n, f->rgb[0]);
    size_t i;
    for(i = 0; i < n && i + 1 < cap; i++) {
        char c = tmp[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        out[i] = ok ? c : '_';
    }
    out[i] = 0;
}

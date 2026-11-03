// Host self-check: SHA-256/HMAC known answers, KDF vectors (independently produced
// by Python hmac/hashlib for UID B0:FA:02:70), and a synthetic tag decode.
// Build: gcc -Wall -Wextra -o test/test_snapmaker test/test_snapmaker.c && ./test/test_snapmaker
#include <stdio.h>
#include <assert.h>
#include "../plugin/snapmaker_parser.h"

static void hex(const uint8_t* d, size_t n, char* out) {
    for(size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02X", d[i]);
}

int main(void) {
    char h[65];
    uint8_t dg[32];
    SmSha256 c;
    sm_sha256_init(&c);
    sm_sha256_update(&c, (const uint8_t*)"abc", 3);
    sm_sha256_final(&c, dg);
    hex(dg, 32, h);
    assert(!strcmp(h, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));

    // RFC 4231 test case 2
    sm_hmac_sha256((const uint8_t*)"Jefe", 4, (const uint8_t*)"what do ya want for nothing?", 28, dg);
    hex(dg, 32, h);
    assert(!strcmp(h, "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"));

    // 64-byte boundary: the SHA-256 padding path for a message that fills a block exactly
    uint8_t sixtyfour[64];
    memset(sixtyfour, 'a', 64);
    sm_sha256_init(&c);
    sm_sha256_update(&c, sixtyfour, 64);
    sm_sha256_final(&c, dg);
    hex(dg, 32, h);
    assert(!strcmp(h, "FFE054FE7AE0CB6DC65C3AF9B61D5209F439851DB43D0BA5997337DF154668EB"));

    const uint8_t uid[4] = {0xB0, 0xFA, 0x02, 0x70};
    uint8_t ka[16][6], kb[16][6];
    sm_derive_keys(uid, ka, kb);
    hex(ka[0], 6, h); assert(!strcmp(h, "99B531AE6BF9"));
    hex(ka[9], 6, h); assert(!strcmp(h, "5FFCA1196E15"));
    hex(ka[10], 6, h); assert(!strcmp(h, "72199440C758"));
    hex(ka[15], 6, h); assert(!strcmp(h, "0EE13CF1A6A9"));
    hex(kb[0], 6, h); assert(!strcmp(h, "755DF9DDF7FB"));
    hex(kb[15], 6, h); assert(!strcmp(h, "09D57BFBB885"));

    uint8_t mem[1024] = {0};
    memcpy(mem, uid, 4);
    memcpy(mem + 16, "Snapmaker", 9);
    memcpy(mem + 32, "Snapmaker", 9);
    mem[64] = 1;             // version
    mem[66] = 20;            // PLA-CF
    mem[68] = 2;             // Matte
    mem[72] = 2;             // two colours
    mem[73] = 0x00;          // alpha stored inverted -> opaque
    mem[80] = 0x12; mem[81] = 0x34; mem[82] = 0x56;
    mem[83] = 0xAB; mem[84] = 0xCD; mem[85] = 0xEF;
    mem[96] = 0x78; mem[97] = 0x56; mem[98] = 0x34; mem[99] = 0x12;
    mem[128] = 175; mem[129] = 0; // 1.75 mm
    mem[130] = 0xE8; mem[131] = 0x03; // 1000 g
    mem[148] = 230; mem[150] = 190;
    mem[154] = 60;
    memcpy(mem + 160, "20250601", 8);
    mem[168] = 3;
    SmFilament f;
    assert(sm_decode(mem, &f));
    assert(!strcmp(f.vendor, "Snapmaker"));
    assert(!strcmp(sm_main_type_name(f.main_type), "PLA-CF"));
    assert(!strcmp(sm_sub_type_name(f.sub_type), "Matte"));
    assert(f.color_count == 2 && f.alpha == 0xFF);
    assert(f.rgb[1][0] == 0xAB && f.rgb[1][2] == 0xEF);
    assert(f.sku == 0x12345678);
    assert(f.diameter_x100 == 175 && f.weight_g == 1000);
    assert(f.hotend_min == 190 && f.hotend_max == 230 && f.bed_temp == 60);
    assert(!strcmp(f.mf_date, "20250601") && f.rsa_key_version == 3);

    mem[66] = 99; // unknown material -> not a Snapmaker tag
    assert(!sm_decode(mem, &f));
    mem[66] = 1; mem[72] = 6; // colour count out of range
    assert(!sm_decode(mem, &f));

    // OpenSpool export
    char json[SM_JSON_MAX];
    uint8_t ndef[512];
    mem[66] = 20; mem[72] = 2; // back to PLA-CF Matte, two colours
    assert(sm_decode(mem, &f));
    size_t jl = sm_openspool_json(&f, json);
    assert(jl == strlen(json));
    assert(!strcmp(json,
        "{\"protocol\":\"openspool\",\"version\":\"1.0\",\"brand\":\"Snapmaker\",\"type\":\"PLA-CF\","
        "\"subtype\":\"Matte\",\"color_hex\":\"123456\",\"additional_color_hexes\":[\"ABCDEF\"],"
        "\"min_temp\":190,\"max_temp\":230,\"bed_min_temp\":60,\"bed_max_temp\":60,\"weight\":1000,\"diameter\":1.75}"));
    // rec_len 266: 3-byte TLV length, short-record NDEF header
    size_t nl = sm_ndef_build(json, jl, ndef, sizeof(ndef));
    size_t rec = 3 + 16 + jl;
    assert(rec > 254 && nl == 4 + rec + 1);
    assert(ndef[0] == 0x03 && ndef[1] == 0xFF && ndef[2] == (rec >> 8) && ndef[3] == (rec & 0xFF));
    assert(ndef[4] == 0xD2 && ndef[5] == 16 && ndef[6] == jl);
    assert(!memcmp(ndef + 7, "application/json", 16) && !memcmp(ndef + 23, json, jl) && ndef[nl - 1] == 0xFE);
    // minimal spool: no temps, weight, diameter -> 2-byte TLV header
    memset(mem + 128, 0, 32); mem[72] = 1;
    assert(sm_decode(mem, &f));
    jl = sm_openspool_json(&f, json);
    assert(!strcmp(json, "{\"protocol\":\"openspool\",\"version\":\"1.0\",\"brand\":\"Snapmaker\",\"type\":\"PLA-CF\",\"subtype\":\"Matte\",\"color_hex\":\"123456\"}"));
    nl = sm_ndef_build(json, jl, ndef, sizeof(ndef));
    assert(nl == 2 + 3 + 16 + jl + 1 && ndef[1] == 3 + 16 + jl && ndef[2] == 0xD2 && ndef[4] == jl && ndef[nl - 1] == 0xFE);
    mem[72] = 2;
    mem[128] = 175; mem[130] = 0xE8; mem[131] = 0x03; mem[148] = 230; mem[150] = 190; mem[154] = 60;
    assert(sm_decode(mem, &f));
    char name[48];
    sm_openspool_name(&f, name, sizeof(name));
    assert(!strcmp(name, "OpenSpool_Snapmaker_PLA_CF_Matte_123456"));

    // Worst case: every field populated, long record + 3-byte TLV length, still fits NTAG215 user memory
    memcpy(mem + 16, "ABCDEFGHIJKLMNOP", 16);
    mem[66] = 17; mem[68] = 13; mem[72] = 5; mem[73] = 0x7F; // PETG-CF Full Spectrum, 5 colours, alpha 128
    mem[128] = 0xFF; mem[129] = 0xFF; mem[130] = 0xFF; mem[131] = 0xFF;
    mem[148] = 0xE7; mem[149] = 0x03; mem[150] = 0xE7; mem[151] = 0x03; mem[154] = 0xE7; mem[155] = 0x03;
    assert(sm_decode(mem, &f) && f.alpha == 128);
    jl = sm_openspool_json(&f, json);
    assert(jl > 255 && strstr(json, "\"alpha\":128") && strstr(json, "\"diameter\":655.35"));
    nl = sm_ndef_build(json, jl, ndef, 504);
    assert(nl && ndef[1] == 0xFF && ndef[4] == 0xC2 && ndef[nl - 1] == 0xFE);
    assert(!sm_ndef_build(json, jl, ndef, 200));
    // single digit fraction gets its zero
    mem[128] = 0x69; mem[129] = 0x00; // 1.05 mm
    assert(sm_decode(mem, &f));
    sm_openspool_json(&f, json);
    assert(strstr(json, "\"diameter\":1.05"));

    puts("ok");
    return 0;
}

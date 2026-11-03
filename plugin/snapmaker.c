// Snapmaker U1 spool tag parser for the stock Flipper NFC app.
#include "nfc_supported_card_plugin.h"
#include <flipper_application/flipper_application.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <furi.h>

#include "snapmaker_parser.h"

static bool snapmaker_read(Nfc* nfc, NfcDevice* device) {
    furi_assert(nfc);
    furi_assert(device);

    bool ok = false;
    MfClassicData* data = mf_classic_alloc();
    nfc_device_copy_data(device, NfcProtocolMfClassic, data);
    // Heap: 496 bytes is too much for the 5 KB NFC thread stack (see flipper-bambu).
    MfClassicDeviceKeys* keys = malloc(sizeof(MfClassicDeviceKeys));

    do {
        if(data->type != MfClassicType1k) break;
        size_t uid_len = 0;
        const uint8_t* uid = nfc_device_get_uid(device, &uid_len);
        if(uid == NULL || uid_len != 4) break;

        uint8_t ka[SM_SECTORS][6], kb[SM_SECTORS][6];
        sm_derive_keys(uid, ka, kb);
        memset(keys, 0, sizeof(*keys));
        for(size_t s = 0; s < SM_SECTORS; s++) {
            memcpy(keys->key_a[s].data, ka[s], 6);
            memcpy(keys->key_b[s].data, kb[s], 6);
            FURI_BIT_SET(keys->key_a_mask, s);
            FURI_BIT_SET(keys->key_b_mask, s);
        }

        // One-block probe: wrong card means a cheap auth failure instead of 32 of them.
        MfClassicBlock probe;
        if(mf_classic_poller_sync_read_block(nfc, 1, &keys->key_a[0], MfClassicKeyTypeA, &probe) !=
           MfClassicErrorNone)
            break;

        MfClassicError err = mf_classic_poller_sync_read(nfc, keys, data);
        if(err != MfClassicErrorNone && err != MfClassicErrorPartialRead) break;
        for(size_t i = 0; i < SM_REQUIRED_BLOCK_COUNT; i++) {
            if(!mf_classic_is_block_read(data, SM_REQUIRED_BLOCKS[i])) goto done;
        }
        nfc_device_set_data(device, NfcProtocolMfClassic, data);
        ok = true;
    } while(false);
done:
    free(keys);
    mf_classic_free(data);
    return ok;
}

// Drop an NTAG215 image carrying the OpenSpool NDEF record into the NFC app's Saved
// list, so "Saved > <file> > Write" onto a blank NTAG215 finishes the conversion
// without leaving the native app. Returns false if it did not fit or did not save.
// ponytail: NTAG215 only; add a 216 variant if that is what the blanks turn out to be.
static bool snapmaker_save_openspool(const SmFilament* f, const uint8_t uid4[4], char* name, size_t name_cap) {
    char json[SM_JSON_MAX];
    size_t json_len = sm_openspool_json(f, json);
    MfUltralightData* mfu = mf_ultralight_alloc();
    bool ok = false;
    do {
        mfu->type = MfUltralightTypeNTAG215;
        mfu->pages_total = 135;
        mfu->pages_read = 135;
        // Pages 0-3 are never written to the blank, but keep the image self-consistent.
        uint8_t uid7[7] = {0x04, uid4[0], uid4[1], uid4[2], uid4[3], 0x5A, 0x4D};
        iso14443_3a_set_uid(mfu->iso14443_3a_data, uid7, 7);
        iso14443_3a_set_atqa(mfu->iso14443_3a_data, (const uint8_t[]){0x44, 0x00});
        iso14443_3a_set_sak(mfu->iso14443_3a_data, 0x00);
        uint8_t* pg = mfu->page[0].data;
        pg[0] = uid7[0]; pg[1] = uid7[1]; pg[2] = uid7[2];
        pg[3] = 0x88 ^ uid7[0] ^ uid7[1] ^ uid7[2];
        memcpy(mfu->page[1].data, uid7 + 3, 4);
        mfu->page[2].data[0] = uid7[3] ^ uid7[4] ^ uid7[5] ^ uid7[6];
        memcpy(mfu->page[3].data, (const uint8_t[]){0xE1, 0x10, 0x3E, 0x00}, 4); // NDEF CC, 504 B
        // User memory is pages 4..129 (504 bytes). 130: dynamic lock, 131-134: CFG0, CFG1, PWD, PACK (factory defaults).
        if(!sm_ndef_build(json, json_len, mfu->page[4].data, 126 * 4)) break;
        memcpy(mfu->page[130].data, (const uint8_t[]){0x00, 0x00, 0x00, 0xBD}, 4);
        memcpy(mfu->page[131].data, (const uint8_t[]){0x04, 0x00, 0x00, 0xFF}, 4);
        memcpy(mfu->page[132].data, (const uint8_t[]){0x00, 0x05, 0x00, 0x00}, 4);
        memset(mfu->page[133].data, 0xFF, 4);
        mfu->version = (MfUltralightVersion){0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03};

        sm_openspool_name(f, name, name_cap);
        FuriString* path = furi_string_alloc_printf("/ext/nfc/%s.nfc", name);
        NfcDevice* dev = nfc_device_alloc();
        nfc_device_set_data(dev, NfcProtocolMfUltralight, mfu);
        ok = nfc_device_save(dev, furi_string_get_cstr(path));
        nfc_device_free(dev);
        furi_string_free(path);
    } while(false);
    mf_ultralight_free(mfu);
    return ok;
}

static bool snapmaker_parse(const NfcDevice* device, FuriString* out) {
    furi_assert(device);
    furi_assert(out);
    const MfClassicData* data = nfc_device_get_data(device, NfcProtocolMfClassic);
    if(data->type != MfClassicType1k) return false;
    for(size_t i = 0; i < SM_REQUIRED_BLOCK_COUNT; i++) {
        if(!mf_classic_is_block_read(data, SM_REQUIRED_BLOCKS[i])) return false;
    }
    // MfClassicBlock is a bare 16-byte array, so block[0..63] is the contiguous 1 KB image.
    SmFilament f;
    if(!sm_decode(data->block[0].data, &f)) return false;

    const char* sub = sm_sub_type_name(f.sub_type);
    furi_string_cat_printf(out, "\e#Snapmaker Filament\n");
    furi_string_cat_printf(out, "Vendor: %s\n", f.vendor);
    if(sub && sub[0]) {
        furi_string_cat_printf(out, "Type: %s %s\n", sm_main_type_name(f.main_type), sub);
    } else if(sub) {
        furi_string_cat_printf(out, "Type: %s\n", sm_main_type_name(f.main_type));
    } else {
        furi_string_cat_printf(out, "Type: %s (sub %u)\n", sm_main_type_name(f.main_type), f.sub_type);
    }
    for(uint8_t i = 0; i < f.color_count; i++) {
        if(f.color_count > 1) {
            furi_string_cat_printf(out, "Color %u: ", i + 1);
        } else {
            furi_string_cat_printf(out, "Color: ");
        }
        furi_string_cat_printf(out, "#%02X%02X%02X", f.rgb[i][0], f.rgb[i][1], f.rgb[i][2]);
        if(f.alpha != 0xFF) furi_string_cat_printf(out, " @ %u%%", (f.alpha * 100) / 255);
        furi_string_cat_printf(out, "\n");
    }
    furi_string_cat_printf(out, "Made: %s\n", f.mf_date);
    if(f.sku) furi_string_cat_printf(out, "SKU: %lu\n", (unsigned long)f.sku);

    furi_string_cat_printf(out, "\n\e#Printing\n");
    furi_string_cat_printf(out, "Hotend: %u-%u C\n", f.hotend_min, f.hotend_max);
    furi_string_cat_printf(out, "Layer 1: %u C, rest: %u C\n", f.first_layer_temp, f.other_layer_temp);
    furi_string_cat_printf(out, "Bed: %u C\n", f.bed_temp);
    furi_string_cat_printf(out, "Drying: %u C for %uh\n", f.dry_temp, f.dry_hours);

    furi_string_cat_printf(out, "\n\e#Spool\n");
    furi_string_cat_printf(out, "Weight: %ug\n", f.weight_g);
    if(f.length_m) furi_string_cat_printf(out, "Length: %um\n", f.length_m);
    furi_string_cat_printf(out, "Diameter: %u.%02umm\n", f.diameter_x100 / 100, f.diameter_x100 % 100);
    furi_string_cat_printf(out, "Signed: RSA key v%u (not verified)\n", f.rsa_key_version);

    char name[48];
    furi_string_cat_printf(out, "\n\e#OpenSpool\n");
    if(snapmaker_save_openspool(&f, data->block[0].data, name, sizeof(name))) {
        furi_string_cat_printf(out, "Saved as %s\nNFC > Saved > that file > Write\nonto a blank NTAG215.\n", name);
    } else {
        furi_string_cat_printf(out, "Could not save NTAG file.\n");
    }
    return true;
}

static const NfcSupportedCardsPlugin snapmaker_plugin = {
    .protocol = NfcProtocolMfClassic,
    .verify = NULL,
    .read = snapmaker_read,
    .parse = snapmaker_parse,
};

static const FlipperAppPluginDescriptor snapmaker_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &snapmaker_plugin,
};

const FlipperAppPluginDescriptor* snapmaker_plugin_ep(void) {
    return &snapmaker_plugin_descriptor;
}

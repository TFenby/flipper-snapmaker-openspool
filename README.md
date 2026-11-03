# Snapmaker + OpenSpool NFC plugin for Flipper Zero

A parser plugin for the Flipper Zero's **stock NFC app**. Scan a Snapmaker U1
filament spool and the NFC app shows the material, colours, temperatures and
spool data instead of a raw MIFARE Classic dump. Each scan also drops an
OpenSpool NTAG215 image into Saved, so writing the same spool as an OpenSpool
tag is two more taps inside the same app.

Works on stock firmware and the forks (Unleashed, Momentum, RogueMaster) as
long as the `.fal` is built against the firmware's own SDK (see Build).

## Install

Copy `snapmaker_parser.fal` to `/ext/apps_data/nfc/plugins/` on the SD card
(qFlipper, or `make deploy` over USB) and restart the NFC app.

## Use

**Decode a spool.** NFC > Read, hold the spool's tag to the Flipper. The plugin
derives the per-tag keys from the UID, reads every sector and shows:

```
Snapmaker Filament
Vendor: Snapmaker
Type: PLA Matte
Color: #1A1A1A
Made: 20250601
...
OpenSpool
Saved as OpenSpool_Snapmaker_PLA_Matte_1A1A1A
NFC > Saved > that file > Write
onto a blank NTAG215.
```

**Write an OpenSpool tag.** NFC > Saved > `OpenSpool_…` > Write, hold a blank
NTAG215 to the Flipper. The tag carries one `application/json` NDEF record using
the OpenSpool schema plus the U1 Extended extensions (`subtype`, `alpha`,
`additional_color_hexes`, `bed_min_temp`/`bed_max_temp`, `weight`, `diameter`).
The Snapmaker U1 reads these with the
[U1 Extended](https://github.com/paxx12-snapmaker-u1/SnapmakerU1-Extended-Firmware)
firmware; stock U1 firmware only reads Snapmaker's signed tags.

**Clone a Snapmaker tag.** The spool data is RSA-signed over a range that
includes the UID, so a copy only works on a UID-changeable (Gen1a) MIFARE
Classic 1K. Save the scan, then write it with the NFC Magic app. The plugin
cannot author new Snapmaker tags and does not verify the signature.

## Build

Needs Python 3 and an internet connection the first time; `make` installs
[ufbt](https://pypi.org/project/ufbt/) into `.venv` and ufbt fetches the SDK and
ARM toolchain into `~/.ufbt`.

```
make            # dist/snapmaker_parser.fal
make deploy     # build, then copy to the Flipper over USB
make test       # host-side checks of the hash, KDF, decoder and NDEF output
```

A `.fal` only loads when its API major matches the firmware. Check
`device_info` on the Flipper (`firmware_api_major`), then point ufbt at the
matching SDK before building:

```
.venv/bin/ufbt update --channel=release                                        # stock
.venv/bin/ufbt update --index-url=https://up.unleashedflip.com/directory.json  # Unleashed, latest
.venv/bin/ufbt update --url=<flipper-z-f7-sdk-*.zip from a specific release>   # anything else
```

CI builds against the current stock and Unleashed release SDKs; grab the
matching artifact from the Actions tab.

## How it works

Snapmaker tags are MIFARE Classic 1K. Both sector keys are HKDF-SHA256 over the
4-byte UID, key A salted with `Snapmaker_qwertyuiop[,.;]` and key B with
`Snapmaker_qwertyuiop[,.;]_1q2w3e`, info `key_<a|b>_<sector>`. Fields live in
sectors 0 to 2 as little-endian integers and ASCII strings; sectors 10 to 15
hold a 2048-bit RSA signature over the first 640 bytes.

- `plugin/snapmaker_parser.h`: SHA-256, HMAC, KDF, field decode, OpenSpool JSON
  and NDEF builders. Plain C, also compiled by the host test.
- `plugin/snapmaker.c`: the Flipper glue (read with derived keys, format, save
  the NTAG image).
- `plugin/nfc_supported_card_plugin.h`: the firmware's plugin interface, vendored
  because the SDK does not ship it.

## Credits

- Key derivation and tag layout: Snapmaker's GPL
  [u1-klipper](https://github.com/Snapmaker/u1-klipper)
  (`fm175xx_reader.py`, `filament_protocol.py`).
- OpenSpool extensions: [U1 Extended](https://github.com/paxx12-snapmaker-u1/SnapmakerU1-Extended-Firmware)
  (`filament_protocol_ndef.py`, `docs/design/openspool.md`).
- Plugin structure: [uzyn/flipper-bambu](https://github.com/uzyn/flipper-bambu).
- OpenSpool: [spuder/OpenSpool](https://github.com/spuder/OpenSpool).

## License

GPL-3.0. See `LICENSE`.

# ufbt comes from a project-local venv unless UFBT points elsewhere (e.g. UFBT=ufbt).
UFBT ?= .venv/bin/ufbt
UFBT_HOME ?= $(HOME)/.ufbt
FLIPPER_PLUGIN_PATH := /ext/apps_data/nfc/plugins/snapmaker_parser.fal

.PHONY: build deploy test clean

.venv/bin/ufbt:
	python3 -m venv .venv && .venv/bin/pip install -q ufbt

build: $(filter .venv/%,$(UFBT))
	$(UFBT)

# ufbt launch only handles EXTERNAL apps; use the SDK's storage.py for a PLUGIN.
deploy: build
	$(UFBT_HOME)/toolchain/current/bin/python3 $(UFBT_HOME)/current/scripts/storage.py \
		send dist/snapmaker_parser.fal $(FLIPPER_PLUGIN_PATH)
	@echo "Deployed. Restart the NFC app to load it."

test: test/test_snapmaker
	./test/test_snapmaker

test/test_snapmaker: test/test_snapmaker.c plugin/snapmaker_parser.h
	gcc -Wall -Wextra -o $@ $<

clean:
	rm -rf dist test/test_snapmaker .vscode
	-$(UFBT) -c >/dev/null 2>&1

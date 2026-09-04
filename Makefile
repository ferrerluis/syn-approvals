PREFIX ?= $(HOME)/.local
CARGO ?= cargo

.PHONY: all build test check fmt lint install-local macos-app package-deb clean verify-fixtures

all: check test

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace
	cd macos && swift test
	$(MAKE) verify-fixtures

check:
	$(CARGO) check --workspace --all-targets

fmt:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

install-local:
	$(CARGO) build --release -p synctl -p syn-agent
	install -d "$(PREFIX)/bin"
	install -m 0755 target/release/synctl "$(PREFIX)/bin/synctl"
	install -m 0755 target/release/syn-agent "$(PREFIX)/bin/syn-agent"

macos-app:
	./scripts/build-macos-app.sh

package-deb:
	./scripts/build-deb.sh

verify-fixtures:
	cmp tests/fixtures/protocol-v1.json macos/Tests/SynTests/Fixtures/protocol-v1.json

clean:
	$(CARGO) clean
	rm -rf macos/.build dist

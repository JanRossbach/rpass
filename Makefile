CARGO = cargo
INSTALL_TARGET = /usr/local/bin/

all: release doc

build:
	@$(CARGO) build

release:
	@$(CARGO) build --release

doc:
	@$(CARGO) doc

check: build test

test:
	@$(CARGO) test

bench:
	@$(CARGO) bench

clean:
	@$(CARGO) clean

debug: build
	rust-gdb -q ./target/debug/rpass

install: release
	sudo cp -v ./target/release/rpass $(INSTALL_TARGET)

.PHONY: build test release

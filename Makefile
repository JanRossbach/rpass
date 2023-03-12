debug:
	cargo build && rust-gdb -q ./target/debug/rpass

install:
	cargo build --release && cp ./target/release/rpass ~/.local/bin/

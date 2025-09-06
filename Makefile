TARGETS = all clean
.PHONY: $(TARGETS)
.SILENT: $(TARGETS)

all:
	# RUSTC_BOOTSTRAP is required in order to use unstable features
	RUSTC_BOOTSTRAP=1 cargo build --release
	polkatool link --strip --output controller.polkavm target/riscv64emac-unknown-none-polkavm/release/main
	polkatool link --strip --output implementation.polkavm target/riscv64emac-unknown-none-polkavm/release/implementation

clean:
	cargo clean

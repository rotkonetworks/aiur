# IBP Contracts Makefile

-include .env
export

.PHONY: all build clean deploy bootstrap test

all: build

build:
	@echo "Building contracts..."
	RUSTC_BOOTSTRAP=1 cargo build --release
	polkatool link --strip --output controller.polkavm \
		target/riscv64emac-unknown-none-polkavm/release/controller
	polkatool link --strip --output implementation.polkavm \
		target/riscv64emac-unknown-none-polkavm/release/implementation

clean:
	cargo clean
	rm -f *.polkavm

deploy: build
	@test -n "$(CHAIN_RPC)" || (echo "Set CHAIN_RPC in .env" && exit 1)
	@test -n "$(PRIVATE_KEY)" || (echo "Set PRIVATE_KEY in .env" && exit 1)
	
	@echo "Deploying to $(CHAIN_RPC)..."
	@echo "Deploying implementation..."
	$(eval IMPL_ADDR := $(shell cast send --private-key $(PRIVATE_KEY) \
		--rpc-url $(CHAIN_RPC) --create \
		"0x$$(xxd -p -c 99999 implementation.polkavm)" \
		--json | jq -r .contractAddress))
	@echo "Implementation deployed at: $(IMPL_ADDR)"
	
	@echo "Deploying controller..."
	$(eval CTRL_ADDR := $(shell cast send --private-key $(PRIVATE_KEY) \
		--rpc-url $(CHAIN_RPC) --create \
		"0x$$(xxd -p -c 99999 controller.polkavm)" \
		--json | jq -r .contractAddress))
	@echo "Controller deployed at: $(CTRL_ADDR)"
	
	@echo "Initializing controller with implementation..."
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CTRL_ADDR) "initialize(address)" $(IMPL_ADDR)
	
	@echo "Updating .env with addresses..."
	@sed -i '/^CONTROLLER_ADDRESS=/d' .env 2>/dev/null || true
	@sed -i '/^IMPLEMENTATION_ADDRESS=/d' .env 2>/dev/null || true
	@echo "CONTROLLER_ADDRESS=$(CTRL_ADDR)" >> .env
	@echo "IMPLEMENTATION_ADDRESS=$(IMPL_ADDR)" >> .env
	@echo ""
	@echo "Deployment complete! Run 'make bootstrap' to initialize."

bootstrap:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Deploy first with 'make deploy'" && exit 1)
	@echo "Bootstrapping controller..."
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "bootstrap()"

# Upgrade implementation
upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(NEW_IMPL_ADDRESS)" || (echo "Set NEW_IMPL_ADDRESS" && exit 1)
	
	cast send --private-key $(PRIVATE_KEY) $(CONTROLLER_ADDRESS) \
		"proposeUpgrade(address)" $(NEW_IMPL_ADDRESS) \
		--rpc-url $(CHAIN_RPC)

# Vote on upgrade
vote:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(SUPPORT)" || (echo "Set SUPPORT=true/false" && exit 1)
	
	cast send --private-key $(PRIVATE_KEY) $(CONTROLLER_ADDRESS) \
		"voteUpgrade(bool)" $(SUPPORT) \
		--rpc-url $(CHAIN_RPC)

# Execute upgrade
execute-upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	
	cast send --private-key $(PRIVATE_KEY) $(CONTROLLER_ADDRESS) \
		"executeUpgrade()" \
		--rpc-url $(CHAIN_RPC)

# Test calls
test-create-network:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	
	cast call $(CONTROLLER_ADDRESS) \
		"createNetwork()" \
		--rpc-url $(CHAIN_RPC)

test-get-implementation:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	
	cast call $(CONTROLLER_ADDRESS) \
		"getImplementation()" \
		--rpc-url $(CHAIN_RPC)

create-network:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS in .env" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "createNetwork()"

# Monitor contract
monitor:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	
	@echo "Monitoring $(CONTROLLER_ADDRESS)..."
	@while true; do \
		echo "Implementation: $$(cast call $(CONTROLLER_ADDRESS) 'getImplementation()')"; \
		echo "Pending: $$(cast call $(CONTROLLER_ADDRESS) 'getPendingUpgrade()')"; \
		sleep 5; \
	done

help:
	@echo "IBP Contracts Management"
	@echo ""
	@echo "Usage:"
	@echo "  make build              - Build contracts"
	@echo "  make deploy             - Deploy contracts"
	@echo "  make bootstrap          - Initialize deployed contracts"
	@echo "  make upgrade NEW_IMPL_ADDRESS=0x... - Propose upgrade"
	@echo "  make vote SUPPORT=true  - Vote on upgrade"
	@echo "  make execute-upgrade    - Execute approved upgrade"
	@echo "  make monitor            - Monitor contract state"
	@echo ""
	@echo "Environment (.env):"
	@echo "  CHAIN_RPC              - RPC endpoint"
	@echo "  PRIVATE_KEY            - Private key for transactions"
	@echo "  CONTROLLER_ADDRESS     - Deployed controller address"
	@echo "  IMPLEMENTATION_ADDRESS - Deployed implementation address"

# IBP Contracts Makefile

# Configuration
CHAIN_RPC ?= http://localhost:8545
ACCOUNT_NAME ?= dev
PRIVATE_KEY ?= 5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133

# Addresses (set after deployment)
CONTROLLER_ADDRESS ?=
IMPLEMENTATION_ADDRESS ?=

.PHONY: all build clean deploy test

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

# Deploy both contracts
deploy: build
	@echo "Importing account..."
	@cast wallet import $(ACCOUNT_NAME) --private-key $(PRIVATE_KEY) 2>/dev/null || true
	
	@echo "Deploying implementation..."
	$(eval IMPL_ADDR := $(shell cast send --account $(ACCOUNT_NAME) --create \
		"$$(xxd -p -c 99999 implementation.polkavm)" \
		--rpc-url $(CHAIN_RPC) --json | jq -r .contractAddress))
	@echo "Implementation deployed at: $(IMPL_ADDR)"
	
	@echo "Deploying controller with implementation..."
	$(eval CTRL_ADDR := $(shell cast send --account $(ACCOUNT_NAME) --create \
		"$$(xxd -p -c 99999 controller.polkavm)$$(echo $(IMPL_ADDR) | cut -c3-)" \
		--rpc-url $(CHAIN_RPC) --json | jq -r .contractAddress))
	@echo "Controller deployed at: $(CTRL_ADDR)"
	
	@echo "export CONTROLLER_ADDRESS=$(CTRL_ADDR)" > .env
	@echo "export IMPLEMENTATION_ADDRESS=$(IMPL_ADDR)" >> .env

# Upgrade implementation
upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(NEW_IMPL_ADDRESS)" || (echo "Set NEW_IMPL_ADDRESS" && exit 1)
	
	cast send --account $(ACCOUNT_NAME) $(CONTROLLER_ADDRESS) \
		"proposeUpgrade(address)" $(NEW_IMPL_ADDRESS) \
		--rpc-url $(CHAIN_RPC)

# Vote on upgrade
vote:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(SUPPORT)" || (echo "Set SUPPORT=true/false" && exit 1)
	
	cast send --account $(ACCOUNT_NAME) $(CONTROLLER_ADDRESS) \
		"voteUpgrade(bool)" $(SUPPORT) \
		--rpc-url $(CHAIN_RPC)

# Execute upgrade
execute-upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	
	cast send --account $(ACCOUNT_NAME) $(CONTROLLER_ADDRESS) \
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
	@echo "  make upgrade NEW_IMPL_ADDRESS=0x... - Propose upgrade"
	@echo "  make vote SUPPORT=true  - Vote on upgrade"
	@echo "  make execute-upgrade    - Execute approved upgrade"
	@echo ""
	@echo "Environment:"
	@echo "  CHAIN_RPC              - RPC endpoint (default: localhost:8545)"
	@echo "  ACCOUNT_NAME           - Cast account name"
	@echo "  PRIVATE_KEY            - Private key for deployment"
	@echo "  CONTROLLER_ADDRESS     - Deployed controller address"

# IBP Contracts Makefile

-include .env
export

.PHONY: all build clean deploy bootstrap test help

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
	@echo "Deploying implementation first..."
	$(eval IMPL_ADDR := $(shell cast send --private-key $(PRIVATE_KEY) \
		--rpc-url $(CHAIN_RPC) --create \
		"0x$$(xxd -p -c 99999 implementation.polkavm)" \
		--json | jq -r .contractAddress))
	@echo "Implementation deployed at: $(IMPL_ADDR)"
	
	@echo "Deploying controller with implementation address appended..."
	$(eval IMPL_BYTES := $(shell echo $(IMPL_ADDR) | sed 's/0x//'))
	$(eval CTRL_ADDR := $(shell cast send --private-key $(PRIVATE_KEY) \
		--rpc-url $(CHAIN_RPC) --create \
		"0x$$(xxd -p -c 99999 controller.polkavm)$$(echo $(IMPL_BYTES))" \
		--json | jq -r .contractAddress))
	@echo "Controller deployed at: $(CTRL_ADDR)"
	
	@echo "Updating .env with addresses..."
	@sed -i '/^CONTROLLER_ADDRESS=/d' .env 2>/dev/null || true
	@sed -i '/^IMPLEMENTATION_ADDRESS=/d' .env 2>/dev/null || true
	@echo "CONTROLLER_ADDRESS=$(CTRL_ADDR)" >> .env
	@echo "IMPLEMENTATION_ADDRESS=$(IMPL_ADDR)" >> .env
	@echo ""
	@echo "Deployment complete! Run 'make bootstrap' to set deployer as level 5."

bootstrap:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Deploy first with 'make deploy'" && exit 1)
	@echo "Bootstrapping: setting deployer as level 5..."
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "bootstrap()"
	@echo "Bootstrap complete! Deployer is now level 5."

# Network management
create-network:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS in .env" && exit 1)
	@echo "Creating new network..."
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "createNetwork()"

add-pylon:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(NETWORK_ID)" || (echo "Set NETWORK_ID" && exit 1)
	@test -n "$(PYLON_ADDRESS)" || (echo "Set PYLON_ADDRESS" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "addPylon(uint32,address)" $(NETWORK_ID) $(PYLON_ADDRESS)

set-network-dns:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(NETWORK_ID)" || (echo "Set NETWORK_ID" && exit 1)
	@test -n "$(ORG_ID)" || (echo "Set ORG_ID (1=IBP, 2=dotters)" && exit 1)
	@test -n "$(ENABLED)" || (echo "Set ENABLED=true/false" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "setNetworkDns(uint32,uint8,bool)" $(NETWORK_ID) $(ORG_ID) $(ENABLED)

# Governance proposals
propose-pylon-level:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PYLON_ADDRESS)" || (echo "Set PYLON_ADDRESS" && exit 1)
	@test -n "$(LEVEL)" || (echo "Set LEVEL (0-9)" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "setPylonLevel(address,uint8)" $(PYLON_ADDRESS) $(LEVEL)

propose-pylon-org:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PYLON_ADDRESS)" || (echo "Set PYLON_ADDRESS" && exit 1)
	@test -n "$(ORG_ID)" || (echo "Set ORG_ID (1=IBP, 2=dotters)" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "setPylonOrg(address,uint8)" $(PYLON_ADDRESS) $(ORG_ID)

propose-dns-controller:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(ORG_ID)" || (echo "Set ORG_ID (1=IBP, 2=dotters)" && exit 1)
	@test -n "$(DNS_CONTROLLER)" || (echo "Set DNS_CONTROLLER address" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "setDnsController(uint8,address)" $(ORG_ID) $(DNS_CONTROLLER)

whitelist-probe:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PROBE_ADDRESS)" || (echo "Set PROBE_ADDRESS" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "whitelistProbe(address)" $(PROBE_ADDRESS)

revoke-probe:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PROBE_ADDRESS)" || (echo "Set PROBE_ADDRESS" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "revokeProbe(address)" $(PROBE_ADDRESS)

# Voting
vote:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PROPOSAL_ID)" || (echo "Set PROPOSAL_ID" && exit 1)
	@test -n "$(SUPPORT)" || (echo "Set SUPPORT=true/false" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "vote(uint32,bool)" $(PROPOSAL_ID) $(SUPPORT)

execute-proposal:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PROPOSAL_ID)" || (echo "Set PROPOSAL_ID" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "executeProposal(uint32)" $(PROPOSAL_ID)

# Upgrade management
propose-upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(NEW_IMPL_ADDRESS)" || (echo "Set NEW_IMPL_ADDRESS" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "proposeUpgrade(address)" $(NEW_IMPL_ADDRESS)

vote-upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(SUPPORT)" || (echo "Set SUPPORT=true/false" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "voteUpgrade(bool)" $(SUPPORT)

execute-upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "executeUpgrade()"

remove-templar:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "removeTemplar()"

# Monitoring
report-probe:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PYLON_ADDRESS)" || (echo "Set PYLON_ADDRESS" && exit 1)
	@test -n "$(REPORT_HASH)" || (echo "Set REPORT_HASH (bytes32)" && exit 1)
	@test -n "$(STATUS_CODE)" || (echo "Set STATUS_CODE (0-254)" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "reportProbeData(address,bytes32,uint8)" \
		$(PYLON_ADDRESS) $(REPORT_HASH) $(STATUS_CODE)

finalize-window:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PYLON_ADDRESS)" || (echo "Set PYLON_ADDRESS" && exit 1)
	@test -n "$(WINDOW)" || (echo "Set WINDOW number" && exit 1)
	cast send --private-key $(PRIVATE_KEY) --rpc-url $(CHAIN_RPC) \
		$(CONTROLLER_ADDRESS) "finalizeWindow(address,uint32)" $(PYLON_ADDRESS) $(WINDOW)

# Query functions
get-implementation:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	cast call $(CONTROLLER_ADDRESS) "getImplementation()" --rpc-url $(CHAIN_RPC)

get-pending-upgrade:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	cast call $(CONTROLLER_ADDRESS) "getPendingUpgrade()" --rpc-url $(CHAIN_RPC)

get-pylon-level:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PYLON_ADDRESS)" || (echo "Set PYLON_ADDRESS" && exit 1)
	cast call $(CONTROLLER_ADDRESS) "getPylonLevel(address)" $(PYLON_ADDRESS) --rpc-url $(CHAIN_RPC)

get-pylon-status:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(PYLON_ADDRESS)" || (echo "Set PYLON_ADDRESS" && exit 1)
	cast call $(CONTROLLER_ADDRESS) "getPylonStatus(address)" $(PYLON_ADDRESS) --rpc-url $(CHAIN_RPC)

get-network-info:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@test -n "$(NETWORK_ID)" || (echo "Set NETWORK_ID" && exit 1)
	cast call $(CONTROLLER_ADDRESS) "getNetworkInfo(uint32)" $(NETWORK_ID) --rpc-url $(CHAIN_RPC)

get-network-count:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	cast call $(CONTROLLER_ADDRESS) "getNetworkCount()" --rpc-url $(CHAIN_RPC)

monitor:
	@test -n "$(CONTROLLER_ADDRESS)" || (echo "Set CONTROLLER_ADDRESS" && exit 1)
	@echo "Monitoring $(CONTROLLER_ADDRESS)..."
	@while true; do \
		echo "=== $$(date) ==="; \
		echo "Implementation: $$(cast call $(CONTROLLER_ADDRESS) 'getImplementation()' --rpc-url $(CHAIN_RPC))"; \
		echo "Pending upgrade: $$(cast call $(CONTROLLER_ADDRESS) 'getPendingUpgrade()' --rpc-url $(CHAIN_RPC))"; \
		echo "Network count: $$(cast call $(CONTROLLER_ADDRESS) 'getNetworkCount()' --rpc-url $(CHAIN_RPC))"; \
		sleep 5; \
	done

help:
	@echo "IBP Contracts Management"
	@echo ""
	@echo "DEPLOYMENT:"
	@echo "  make deploy                        - Deploy contracts"
	@echo "  make bootstrap                     - Set deployer as level 5"
	@echo ""
	@echo "NETWORK MANAGEMENT:"
	@echo "  make create-network                - Create new network"
	@echo "  make add-pylon NETWORK_ID=1 PYLON_ADDRESS=0x..."
	@echo "  make set-network-dns NETWORK_ID=1 ORG_ID=1 ENABLED=true"
	@echo ""
	@echo "GOVERNANCE:"
	@echo "  make propose-pylon-level PYLON_ADDRESS=0x... LEVEL=6"
	@echo "  make propose-pylon-org PYLON_ADDRESS=0x... ORG_ID=1"
	@echo "  make propose-dns-controller ORG_ID=1 DNS_CONTROLLER=0x..."
	@echo "  make whitelist-probe PROBE_ADDRESS=0x..."
	@echo "  make vote PROPOSAL_ID=1 SUPPORT=true"
	@echo "  make execute-proposal PROPOSAL_ID=1"
	@echo ""
	@echo "UPGRADES:"
	@echo "  make propose-upgrade NEW_IMPL_ADDRESS=0x..."
	@echo "  make vote-upgrade SUPPORT=true"
	@echo "  make execute-upgrade"
	@echo "  make remove-templar"
	@echo ""
	@echo "MONITORING:"
	@echo "  make report-probe PYLON_ADDRESS=0x... REPORT_HASH=0x... STATUS_CODE=0"
	@echo "  make finalize-window PYLON_ADDRESS=0x... WINDOW=12345"
	@echo "  make monitor"
	@echo ""
	@echo "QUERIES:"
	@echo "  make get-implementation"
	@echo "  make get-pylon-level PYLON_ADDRESS=0x..."
	@echo "  make get-pylon-status PYLON_ADDRESS=0x..."
	@echo "  make get-network-info NETWORK_ID=1"

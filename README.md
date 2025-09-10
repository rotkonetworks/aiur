# aiur

aiur is a smart contract system for the Infrastructure Builders' Program (IBP)
that handles network governance, member management and decentralized monitoring
with on-chain verified SLA tracking.

## overview

the system consists of two contracts:
- **controller (proxy)**: handles upgrades and delegation
- **implementation**: core logic for IBP operations

### key feats

- **network management**: create and manage multiple networks with different level requirements
- **member governance**: democratic voting for level changes, org assignments, and DNS control
- **decentralized monitoring**: whitelisted probes report pylon health with hash-based verification
- **SLA tracking**: onchain consensus for payment eligibility based on uptime

## architecture

### storage layout
- shared prefix `0x10` for pylon levels (accessible by both contracts)
- implementation uses `0x20-0x40` for its storage
- controller uses `0xA1-0xA7` for upgrade management

### monitoring system
- probes report every 5 minutes (300 seconds)
- each report contains: 32-byte IPFS hash + 1-byte status code
- status codes: 0-127 (healthy), 128-255 (degraded/error)
- 2/3 consensus required for window finalization

## building

```bash
# install dependencies
cargo install polkatool

# build contracts
make build

# output files:
# - controller.polkavm
# - implementation.polkavm
```

## deployment

the system supports two deployment flows:

### two-step initialization
deploy contracts with initial funding, then initialize separately:

```bash
# deploy with funding (1 ETH default, adjustable via CREATE_VALUE)
make deploy CREATE_VALUE=1000000000000000000

# bootstrap the system (set deployer as initial templar)
make bootstrap
```

### eof-init (single step)
append implementation address to controller bytecode for atomic deployment:

```bash
# deploy and initialize in one transaction
make deploy-eof CREATE_VALUE=1000000000000000000
```

both methods:
- fund contracts with value to prevent storage write traps
- set deployer as templar with emergency upgrade powers
- templar can be permanently removed via `removeTemplar()`

### manual deployment

```bash
# deploy implementation first (with funding)
IMPL_ADDR=$(cast send --create --value 1ether \
  "0x$(xxd -p -c 99999 implementation.polkavm)" \
  --account dev --json | jq -r .contractAddress)

# two-step: deploy controller, then initialize
CTRL_ADDR=$(cast send --create --value 1ether \
  "0x$(xxd -p -c 99999 controller.polkavm)" \
  --account dev --json | jq -r .contractAddress)
cast send $CTRL_ADDR "initialize(address)" $IMPL_ADDR

# eof-init: append implementation address to bytecode
CTRL_ADDR=$(cast send --create --value 1ether \
  "0x$(xxd -p -c 99999 controller.polkavm)$(echo $IMPL_ADDR | cut -c3-)" \
  --account dev --json | jq -r .contractAddress)

# all interactions go through the controller
export CONTRACT=$CTRL_ADDR
```

## usage

### network operations

```bash
# create a network (requires level 5+)
cast send $CONTRACT "createNetwork()"

# add pylon to network
cast send $CONTRACT "addPylon(uint32,address)" 1 0xPYLON_ADDRESS

# set DNS for network
cast send $CONTRACT "setNetworkDns(uint32,uint8,bool)" 1 1 true
```

### governance

```bash
# propose level change (creates proposal)
cast send $CONTRACT "setPylonLevel(address,uint8)" 0xPYLON 6

# vote on proposal
cast send $CONTRACT "vote(uint32,bool)" 1 true

# execute proposal (requires 2/3 majority)
cast send $CONTRACT "executeProposal(uint32)" 1
```

### monitoring

```bash
# whitelist probe (via governance)
cast send $CONTRACT "whitelistProbe(address)" 0xPROBE

# report monitoring data (probe only)
# statusCode: 0-127 healthy, 128-255 error
cast send $CONTRACT "reportProbeData(address,bytes32,uint8)" \
  0xPYLON 0xIPFS_HASH 0

# finalize window (anyone can call after window ends)
cast send $CONTRACT "finalizeWindow(address,uint32)" 0xPYLON 12345
```

### queries

```bash
# get pylon level
cast call $CONTRACT "getPylonLevel(address)" 0xPYLON

# get pylon status (0=healthy, 1=degraded, 2=insufficient, 128+=error)
cast call $CONTRACT "getPylonStatus(address)" 0xPYLON

# get network info
cast call $CONTRACT "getNetworkInfo(uint32)" 1
```

## contract upgrades

```bash
# deploy new implementation
NEW_IMPL=$(cast send --create "$(xxd -p -c 99999 new_impl.polkavm)" \
  --json | jq -r .contractAddress)

# propose upgrade (any level 5+)
cast send $CONTRACT "proposeUpgrade(address)" $NEW_IMPL

# vote on upgrade
cast send $CONTRACT "voteUpgrade(bool)" true

# execute upgrade (48h timelock unless templar)
cast send $CONTRACT "executeUpgrade()"
```

## status code reference

| range | meaning | description |
|-------|---------|-------------|
| 0-127 | healthy | node operational, can encode latency |
| 128-199 | degraded | partially functional |
| 200 | offline | node unreachable |
| 201 | wrong chain | incorrect network |
| 202 | not synced | node syncing |
| 203 | no peers | insufficient connectivity |

## security

- upgrades require 2/3 majority vote from level 5+ pylons
- 48-hour timelock on upgrades (templar can bypass once)
- collision-resistant storage keys using keccak256
- one report per probe per window enforcement

## license

Apache-2.0

# aiur

smart contract system for the Infrastructure Builders' Program (IBP) - handles
network governance, member management, and decentralized monitoring with
on-chain SLA tracking.

## architecture

- **controller**: upgradeable proxy, handles delegation and upgrade governance
- **implementation**: core IBP logic - networks, pylons, proposals, monitoring

deployed atomically with implementation address appended to controller bytecode.
no separate initialization step.

## storage layout

```
0x10: pylon levels (shared)
0x20-0x40: implementation storage
0xA1-0xA8: controller storage (upgrades)
```

## deployment

```bash
# build
make build

# deploy both contracts
make deploy

# set deployer as level 5
make bootstrap
```

contracts require funding (1 NATIVE_TOKEN default) to prevent storage write traps.

## core operations

### networks
```bash
# create network (level 5+ required)
make create-network

# add pylon to network
make add-pylon NETWORK_ID=1 PYLON_ADDRESS=0x...

# configure DNS
make set-network-dns NETWORK_ID=1 ORG_ID=1 ENABLED=true
```

### governance
```bash
# propose changes (level 5+)
make propose-pylon-level PYLON_ADDRESS=0x... LEVEL=6
make whitelist-probe PROBE_ADDRESS=0x...

# vote (level 5-7, equal weight)
make vote PROPOSAL_ID=1 SUPPORT=true

# execute (2/3 majority required)
make execute-proposal PROPOSAL_ID=1
```

### monitoring
```bash
# probe reports (every 5 min)
make report-probe PYLON_ADDRESS=0x... REPORT_HASH=0x... STATUS_CODE=0

# finalize window (requires 3+ reports)
make finalize-window PYLON_ADDRESS=0x... WINDOW=12345
```

status codes:
- 0-127: healthy
- 128-199: degraded  
- 200-254: error states
- 255: reserved (rejected)

### upgrades
```bash
# propose new implementation
make propose-upgrade NEW_IMPL_ADDRESS=0x...

# vote
make vote-upgrade SUPPORT=true

# execute (48h timelock, templar can bypass)
make execute-upgrade

# remove templar privilege
make remove-templar
```

## query functions

```bash
make get-implementation
make get-pylon-level PYLON_ADDRESS=0x...
make get-pylon-status PYLON_ADDRESS=0x...
make get-network-info NETWORK_ID=1
```

## consensus math

uses ceiling division for 2/3 majority: `(total * 2 + 2) / 3`
- 3 votes → need 2
- 4 votes → need 3
- 5 votes → need 4

## security

- collision-resistant storage keys via keccak256
- one report per probe per window
- versioned voting keys prevent cross-proposal replay
- zero address and code size validation
- 48h upgrade timelock (except templar)

## license

Apache-2.0

#![feature(alloc_error_handler)]
#![no_main]
#![no_std]
#![allow(static_mut_refs)]

use uapi::{HostFn, HostFnImpl as api, ReturnFlags, StorageFlags};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp");
        core::hint::unreachable_unchecked();
    }
}

// minimal bump allocator for `alloc`
mod alloc_support {
    use core::{
        alloc::{GlobalAlloc, Layout},
        sync::atomic::{AtomicUsize, Ordering},
    };

    pub struct BumpAllocator {
        offset: AtomicUsize,
    }

    const HEAP_SIZE: usize = 64 * 1024;

    #[link_section = ".bss.heap"]
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

    unsafe impl GlobalAlloc for BumpAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let align = layout.align().max(8);
            let size = layout.size();
            let mut offset = self.offset.load(Ordering::Relaxed);
            loop {
                let aligned = (offset + align - 1) & !(align - 1);
                if aligned + size > HEAP_SIZE {
                    return core::ptr::null_mut();
                }
                match self.offset.compare_exchange_weak(
                    offset,
                    aligned + size,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let heap_ptr = HEAP.as_ptr() as *mut u8;
                        return heap_ptr.add(aligned);
                    },
                    Err(o) => offset = o,
                }
            }
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static GLOBAL: BumpAllocator = BumpAllocator { offset: AtomicUsize::new(0) };

    #[alloc_error_handler]
    fn alloc_error(_layout: Layout) -> ! {
        unsafe {
            core::arch::asm!("unimp");
            core::hint::unreachable_unchecked();
        }
    }
}

// tiny adapters for storage apis
#[inline(always)]
fn sset(key: &[u8], value: &[u8]) {
    let _ = api::set_storage(StorageFlags::empty(), key, value);
}
#[inline(always)]
fn sget(key: &[u8], out: &mut [u8]) {
    let mut slice = &mut out[..];
    let _ = api::get_storage(StorageFlags::empty(), key, &mut slice);
}

// ---- selectors ----

#[inline(always)]
fn sel(signature: &str) -> [u8; 4] {
    let mut h = [0u8; 32];
    api::hash_keccak_256(signature.as_bytes(), &mut h);
    [h[0], h[1], h[2], h[3]]
}

// ---- storage layout ----

// shared with controller: same prefix for pylon levels
const PYLON_LEVEL_PREFIX: u8 = 0x10;

// implementation-only keys and prefixes
const NETWORK_COUNT_KEY: [u8; 32] = [0x20; 32];
const PROPOSAL_COUNT_KEY: [u8; 32] = [0x21; 32];

const NETWORK_PREFIX: u8 = 0x30;
const PYLON_PREFIX: u8 = 0x31;
const DNS_PREFIX: u8 = 0x32;
const ORG_PREFIX: u8 = 0x33;
const PYLON_ORG_PREFIX: u8 = 0x34;
const DNS_CONTROLLER_PREFIX: u8 = 0x35;
const PROPOSAL_PREFIX: u8 = 0x36;
const VOTE_PREFIX: u8 = 0x37;
const VOTE_WEIGHT_PREFIX: u8 = 0x38;
const PROBE_WINDOW_PREFIX: u8 = 0x39;
const PROBE_REPORT_PREFIX: u8 = 0x3A;
const PYLON_STATUS_PREFIX: u8 = 0x3B;
const PROPOSAL_DATA_PREFIX: u8 = 0x3C;
const PROBE_WHITELIST_PREFIX: u8 = 0x3D;
const PYLON_METRICS_PREFIX: u8 = 0x3E;
const WINDOW_FINALIZED_PREFIX: u8 = 0x3F;
const PROPOSAL_EXECUTED_PREFIX: u8 = 0x40;

// monitoring constants
const REPORT_INTERVAL: u64 = 300;
const MIN_PROBES_FOR_CONSENSUS: u8 = 3;

// ---- key helpers ----

#[inline(always)]
fn pylon_level_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_LEVEL_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

#[inline(always)]
fn network_key(id: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = NETWORK_PREFIX;
    key[1..5].copy_from_slice(&id.to_le_bytes());
    key
}

#[inline(always)]
fn pylon_key(network_id: u32, pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_PREFIX;
    key[1..5].copy_from_slice(&network_id.to_le_bytes());
    key[5..25].copy_from_slice(pylon);
    key
}

#[inline(always)]
fn dns_key(network_id: u32, org_id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = DNS_PREFIX;
    key[1..5].copy_from_slice(&network_id.to_le_bytes());
    key[5] = org_id;
    key
}

#[inline(always)]
fn org_key(org_id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = ORG_PREFIX;
    key[1] = org_id;
    key
}

#[inline(always)]
fn pylon_org_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_ORG_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

#[inline(always)]
fn dns_controller_key(org_id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = DNS_CONTROLLER_PREFIX;
    key[1] = org_id;
    key
}

#[inline(always)]
fn proposal_key(id: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROPOSAL_PREFIX;
    key[1..5].copy_from_slice(&id.to_le_bytes());
    key
}

#[inline(always)]
fn proposal_executed_key(id: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = PROPOSAL_EXECUTED_PREFIX;
    k[1..5].copy_from_slice(&id.to_le_bytes());
    k
}

#[inline(always)]
fn proposal_data_key(id: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROPOSAL_DATA_PREFIX;
    key[1..5].copy_from_slice(&id.to_le_bytes());
    key
}

#[inline(always)]
fn vote_key(proposal_id: u32, voter: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = VOTE_PREFIX;
    key[1..5].copy_from_slice(&proposal_id.to_le_bytes());
    key[5..25].copy_from_slice(voter);
    key
}

#[inline(always)]
fn vote_weight_key(proposal_id: u32, support: bool) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = VOTE_WEIGHT_PREFIX;
    key[1..5].copy_from_slice(&proposal_id.to_le_bytes());
    key[5] = support as u8;
    key
}

#[inline(always)]
fn probe_window_key(pylon: &[u8; 20], window: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROBE_WINDOW_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key[21..25].copy_from_slice(&window.to_le_bytes());
    key
}

#[inline(always)]
fn window_finalized_key(pylon: &[u8; 20], window: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = WINDOW_FINALIZED_PREFIX;
    k[1..21].copy_from_slice(pylon);
    k[21..25].copy_from_slice(&window.to_le_bytes());
    k
}

/// collision-proof report key: keccak(pylon || window || probe)
#[inline(always)]
fn probe_report_key(pylon: &[u8; 20], window: u32, probe: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 44];
    buf[0..20].copy_from_slice(pylon);
    buf[20..24].copy_from_slice(&window.to_le_bytes());
    buf[24..44].copy_from_slice(probe);

    let mut h = [0u8; 32];
    api::hash_keccak_256(&buf, &mut h);

    let mut key = [0u8; 32];
    key[0] = PROBE_REPORT_PREFIX;
    key[1..32].copy_from_slice(&h[..31]);
    key
}

/// returns a pylon's status key
#[inline(always)]
fn pylon_status_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_STATUS_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

/// returns pylon's metrics key
#[inline(always)]
fn pylon_metrics_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_METRICS_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

/// returns probe's whitelist key
#[inline(always)]
fn probe_whitelist_key(probe: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROBE_WHITELIST_PREFIX;
    key[1..21].copy_from_slice(probe);
    key
}

#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
    // sets initial org labels and zeroes counters
    sset(&org_key(1), b"IBP");
    sset(&org_key(2), b"dotters");
    sset(&NETWORK_COUNT_KEY, &0u32.to_le_bytes());
    sset(&PROPOSAL_COUNT_KEY, &0u32.to_le_bytes());
}

#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
    let mut selector = [0u8; 4];
    api::call_data_copy(&mut selector, 0);

    // compute all selectors we support (runtime-keccak)
    let s_create_network = sel("createNetwork()");
    let s_set_network_dns = sel("setNetworkDns(uint32,uint8,bool)");
    let s_add_pylon = sel("addPylon(uint32,address)");
    let s_remove_pylon = sel("removePylon(uint32,address)");
    let s_set_pylon_org = sel("setPylonOrg(address,uint8)");
    let s_set_pylon_level = sel("setPylonLevel(address,uint8)");
    let s_set_dns_controller = sel("setDnsController(uint8,address)");
    let s_get_dns_controller = sel("getDnsController(uint8)");
    let s_whitelist_probe = sel("whitelistProbe(address)");
    let s_revoke_probe = sel("revokeProbe(address)");
    let s_is_probe_whitelisted = sel("isProbeWhitelisted(address)");
    let s_propose = sel("propose(uint8)");
    let s_vote = sel("vote(uint32,bool)");
    let s_execute_proposal = sel("executeProposal(uint32)");
    let s_get_network_info = sel("getNetworkInfo(uint32)");
    let s_get_network_count = sel("getNetworkCount()");
    let s_get_proposal = sel("getProposal(uint32)");
    let s_get_pylon_level = sel("getPylonLevel(address)");
    let s_get_pylon_status = sel("getPylonStatus(address)");
    let s_get_pylon_metrics = sel("getPylonMetrics(address)");
    let s_report_probe_data = sel("reportProbeData(address,bytes32,uint8)");
    let s_finalize_window = sel("finalizeWindow(address,uint32)");
    let s_bootstrap = sel("bootstrap()");

    match selector {
        x if x == s_bootstrap => bootstrap(),
        x if x == s_create_network => create_network(),
        x if x == s_set_network_dns => set_network_dns(),
        x if x == s_add_pylon => add_pylon(),
        x if x == s_remove_pylon => remove_pylon(),
        x if x == s_set_pylon_org => set_pylon_org(),
        x if x == s_set_pylon_level => set_pylon_level(),
        x if x == s_set_dns_controller => set_dns_controller(),
        x if x == s_get_dns_controller => get_dns_controller(),
        x if x == s_whitelist_probe => whitelist_probe(),
        x if x == s_revoke_probe => revoke_probe(),
        x if x == s_is_probe_whitelisted => is_probe_whitelisted(),
        x if x == s_propose => propose(),
        x if x == s_vote => vote(),
        x if x == s_execute_proposal => execute_proposal(),
        x if x == s_get_network_info => get_network_info(),
        x if x == s_get_network_count => get_network_count(),
        x if x == s_get_proposal => get_proposal(),
        x if x == s_get_pylon_level => get_pylon_level(),
        x if x == s_get_pylon_status => get_pylon_status(),
        x if x == s_get_pylon_metrics => get_pylon_metrics(),
        x if x == s_report_probe_data => report_probe_data(),
        x if x == s_finalize_window => finalize_window(),
        _ => api::return_value(ReturnFlags::REVERT, &[]),
    }
}

/// one-time bootstrap to set deployer as templar
fn bootstrap() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);
    
    let mut level = [0u8; 1];
    sget(&pylon_level_key(&caller), &mut level);
    if level[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already bootstrapped");
    }
    
    sset(&pylon_level_key(&caller), &[5u8]);
    api::return_value(ReturnFlags::empty(), &[]);
}

/// creates a new network; caller must be level 5+; caller becomes initial pylon of that network
///
/// returns: `uint32 network_id`
fn create_network() {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut level = [0u8; 1];
    sget(&pylon_level_key(&caller), &mut level);
    if level[0] < 5 {
        api::return_value(ReturnFlags::REVERT, b"need level 5+");
    }

    let mut count_bytes = [0u8; 4];
    sget(&NETWORK_COUNT_KEY, &mut count_bytes);
    let mut count = u32::from_le_bytes(count_bytes);
    count = count.saturating_add(1);

    let network_id = count;
    sset(&NETWORK_COUNT_KEY, &count.to_le_bytes());
    sset(&network_key(network_id), &level);
    sset(&pylon_key(network_id, &caller), &[1u8]); // mark as member

    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&network_id.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &out);
}

/// sets dns enable flag for an org on a given network; controller or level 5+ pylon is required
fn set_network_dns() {
    let mut input = [0u8; 96]; // selector-skipped args (3 slots)
    api::call_data_copy(&mut input, 4);

    let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
    let org_id = input[63];
    let enabled = input[95] != 0;

    if !(org_id == 1 || org_id == 2) {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
    }

    // ensure network exists
    let mut level_req = [0u8; 1];
    sget(&network_key(network_id), &mut level_req);
    if level_req[0] == 0 {
        api::return_value(ReturnFlags::REVERT, b"network not found");
    }

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut controller = [0u8; 20];
    sget(&dns_controller_key(org_id), &mut controller);

    let mut is_pylon = [0u8; 1];
    sget(&pylon_key(network_id, &caller), &mut is_pylon);

    let mut level = [0u8; 1];
    sget(&pylon_level_key(&caller), &mut level);

    if caller != controller && (is_pylon[0] == 0 || level[0] < 5) {
        api::return_value(ReturnFlags::REVERT, b"not authorized");
    }

    sset(&dns_key(network_id, org_id), &[enabled as u8]);
    api::return_value(ReturnFlags::empty(), &[]);
}

/// adds a pylon to a network; caller must be a level 5+ pylon of that network
fn add_pylon() {
    let mut input = [0u8; 64]; // 2 slots
    api::call_data_copy(&mut input, 4);

    let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
    let mut new_pylon = [0u8; 20];
    new_pylon.copy_from_slice(&input[44..64]);

    // ensure network exists
    let mut net_data = [0u8; 1];
    sget(&network_key(network_id), &mut net_data);
    if net_data[0] == 0 {
        api::return_value(ReturnFlags::REVERT, b"network not found");
    }

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut is_pylon = [0u8; 1];
    sget(&pylon_key(network_id, &caller), &mut is_pylon);

    let mut level = [0u8; 1];
    sget(&pylon_level_key(&caller), &mut level);

    if is_pylon[0] == 0 || level[0] < 5 {
        api::return_value(ReturnFlags::REVERT, b"not authorized");
    }

    sset(&pylon_key(network_id, &new_pylon), &[1u8]);
    sset(&pylon_status_key(&new_pylon), &[0u8]); // default as healthy
    api::return_value(ReturnFlags::empty(), &[]);
}

/// removing a pylon must be done via governance
fn remove_pylon() {
    api::return_value(ReturnFlags::REVERT, b"use governance");
}

/// creates a proposal to set a pylon's org; only level 5+ may propose
///
/// returns: `uint32 proposal_id`
fn set_pylon_org() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);
    let org_id = input[63];

    if !(org_id == 1 || org_id == 2) {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
    }

    create_proposal(2, &pylon, org_id);
}

/// creates a proposal to set a pylon's level; only level 5+ may propose
///
/// returns: `uint32 proposal_id`
fn set_pylon_level() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);
    let new_level = input[63];

    if new_level > 9 {
        api::return_value(ReturnFlags::REVERT, b"max level 9");
    }

    create_proposal(1, &pylon, new_level);
}

/// creates a proposal to set dns controller for an org
///
/// returns: `uint32 proposal_id`
fn set_dns_controller() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let org_id = input[31];
    let mut controller = [0u8; 20];
    controller.copy_from_slice(&input[44..64]);

    if !(org_id == 1 || org_id == 2) {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
    }

    create_proposal(3, &controller, org_id);
}

/// creates a proposal to whitelist a probe
///
/// returns: `uint32 proposal_id`
fn whitelist_probe() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&input[12..32]);

    create_proposal(4, &probe, 1);
}

/// creates a proposal to revoke a probe
///
/// returns: `uint32 proposal_id`
fn revoke_probe() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&input[12..32]);

    create_proposal(5, &probe, 0);
}

/// creates a governance proposal (internal helper)
fn create_proposal(proposal_type: u8, target: &[u8; 20], value: u8) {
    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut level = [0u8; 1];
    sget(&pylon_level_key(&caller), &mut level);
    if level[0] < 5 {
        api::return_value(ReturnFlags::REVERT, b"need level 5+");
    }

    let mut count_bytes = [0u8; 4];
    sget(&PROPOSAL_COUNT_KEY, &mut count_bytes);
    let mut count = u32::from_le_bytes(count_bytes);
    count = count.saturating_add(1);

    // meta: [0]=type, [1..21]=proposer
    let mut meta = [0u8; 32];
    meta[0] = proposal_type;
    meta[1..21].copy_from_slice(&caller);
    sset(&proposal_key(count), &meta);

    // data: [0..20]=target, [20]=value
    let mut data = [0u8; 32];
    data[0..20].copy_from_slice(target);
    data[20] = value;
    sset(&proposal_data_key(count), &data);

    sset(&PROPOSAL_COUNT_KEY, &count.to_le_bytes());

    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&count.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &out);
}

/// generic propose entrypoint is disabled to avoid abi misuse
fn propose() {
    api::return_value(ReturnFlags::REVERT, b"use typed propose");
}

/// casts a vote on a proposal; equal weight for levels 5..7
///
/// returns: `uint16 tally_for_side`
fn vote() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
    let support = input[63] != 0;

    let mut voter = [0u8; 20];
    api::caller(&mut voter);

    let mut level = [0u8; 1];
    sget(&pylon_level_key(&voter), &mut level);
    if level[0] < 5 {
        api::return_value(ReturnFlags::REVERT, b"need level 5+");
    }

    let mut existing = [0u8; 1];
    sget(&vote_key(proposal_id, &voter), &mut existing);
    if existing[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already voted");
    }

    let weight = calculate_vote_weight(level[0]);
    sset(&vote_key(proposal_id, &voter), &[support as u8 + 1]);

    let mut tall = [0u8; 2];
    sget(&vote_weight_key(proposal_id, support), &mut tall);
    let mut tally = u16::from_le_bytes(tall);
    tally = tally.saturating_add(weight as u16);
    sset(&vote_weight_key(proposal_id, support), &tally.to_le_bytes());

    let mut out = [0u8; 32];
    out[30..32].copy_from_slice(&tally.to_le_bytes());
    api::return_value(ReturnFlags::empty(), &out);
}

/// executes a proposal if a 2/3 majority is met
fn execute_proposal() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);

    // prevent re-execution
    let mut ex = [0u8; 1];
    sget(&proposal_executed_key(proposal_id), &mut ex);
    if ex[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already executed");
    }

    let mut yes_bytes = [0u8; 2];
    sget(&vote_weight_key(proposal_id, true), &mut yes_bytes);
    let yes = u16::from_le_bytes(yes_bytes);

    let mut no_bytes = [0u8; 2];
    sget(&vote_weight_key(proposal_id, false), &mut no_bytes);
    let no = u16::from_le_bytes(no_bytes);

    let total = yes + no;
    // use ceiling division: (total * 2 + 2) / 3
    let threshold = (total * 2 + 2) / 3;
    if total == 0 || yes < threshold {
        api::return_value(ReturnFlags::REVERT, b"need 2/3 majority");
    }

    let mut meta = [0u8; 32];
    sget(&proposal_key(proposal_id), &mut meta);
    let ptype = meta[0];

    match ptype {
        1 => apply_set_pylon_level(proposal_id),
        2 => apply_set_pylon_org(proposal_id),
        3 => apply_set_dns_controller(proposal_id),
        4 => apply_whitelist_probe(proposal_id),
        5 => apply_revoke_probe(proposal_id),
        _ => api::return_value(ReturnFlags::REVERT, b"invalid type"),
    }

    // mark executed
    sset(&proposal_executed_key(proposal_id), &[1u8]);
    
    // return proposal ID for monitoring
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&proposal_id.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &out);
}

/// applies a pylon level change decided by governance
fn apply_set_pylon_level(proposal_id: u32) {
    let mut data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut data);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&data[0..20]);
    let new_level = data[20];

    sset(&pylon_level_key(&pylon), &[new_level]);
}

/// applies a pylon org change decided by governance
fn apply_set_pylon_org(proposal_id: u32) {
    let mut data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut data);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&data[0..20]);
    let org_id = data[20];

    sset(&pylon_org_key(&pylon), &[org_id]);
}

/// applies a dns controller change decided by governance
fn apply_set_dns_controller(proposal_id: u32) {
    let mut data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut data);

    let mut controller = [0u8; 20];
    controller.copy_from_slice(&data[0..20]);
    let org_id = data[20];

    sset(&dns_controller_key(org_id), &controller);
}

/// whitelists a probe decided by governance
fn apply_whitelist_probe(proposal_id: u32) {
    let mut data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut data);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&data[0..20]);

    sset(&probe_whitelist_key(&probe), &[1u8]);
}

/// revokes a probe decided by governance
fn apply_revoke_probe(proposal_id: u32) {
    let mut data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut data);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&data[0..20]);

    sset(&probe_whitelist_key(&probe), &[0u8]);
}

/// returns network info: level requirement and org dns flags
///
/// returns: `(uint8 level_requirement, bool ibp_dns_enabled, bool dotters_dns_enabled)`
fn get_network_info() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);

    let mut level_req = [0u8; 1];
    sget(&network_key(network_id), &mut level_req);

    let mut ibp_dns = [0u8; 1];
    sget(&dns_key(network_id, 1), &mut ibp_dns);

    let mut dotters_dns = [0u8; 1];
    sget(&dns_key(network_id, 2), &mut dotters_dns);

    // abi: 3 slots (96 bytes)
    let mut out = [0u8; 96];
    out[31] = level_req[0];
    out[63] = ibp_dns[0];
    out[95] = dotters_dns[0];
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns the total number of networks
///
/// returns: `uint32 count`
fn get_network_count() {
    let mut count_bytes = [0u8; 4];
    sget(&NETWORK_COUNT_KEY, &mut count_bytes);
    let count = u32::from_le_bytes(count_bytes);

    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&count.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns dns controller for an org
///
/// returns: `address controller`
fn get_dns_controller() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let org_id = input[31];
    if !(org_id == 1 || org_id == 2) {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
    }

    let mut controller = [0u8; 20];
    sget(&dns_controller_key(org_id), &mut controller);

    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&controller);
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns proposal meta info
///
/// returns: `(uint8 proposal_type, address proposer)`
fn get_proposal() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);

    let mut meta = [0u8; 32];
    sget(&proposal_key(proposal_id), &mut meta);

    let mut out = [0u8; 64];
    out[31] = meta[0];
    out[44..64].copy_from_slice(&meta[1..21]);
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns a pylon's level
///
/// returns: `uint8 level`
fn get_pylon_level() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);

    let mut level = [0u8; 1];
    sget(&pylon_level_key(&pylon), &mut level);

    let mut out = [0u8; 32];
    out[31] = level[0];
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns a pylon's current status
///
/// status: 0 healthy, 1 degraded, 2 insufficient reports, 128+ errors
///
/// returns: `uint8 status`
fn get_pylon_status() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);

    let mut status = [0u8; 1];
    sget(&pylon_status_key(&pylon), &mut status);

    let mut out = [0u8; 32];
    out[31] = status[0];
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns aggregated pylon metrics for the last finalized window
///
/// returns: `(uint8 status, uint16 avg_latency, uint8 total_count, uint8 healthy_count, uint32 window)`
fn get_pylon_metrics() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);

    let mut m = [0u8; 10];
    sget(&pylon_metrics_key(&pylon), &mut m);

    let mut out = [0u8; 160]; // 5 slots
    out[31] = m[0];                        // status
    out[62..64].copy_from_slice(&m[1..3]); // avg_latency
    out[95] = m[3];                        // total_count
    out[127] = m[4];                       // healthy_count
    out[156..160].copy_from_slice(&m[6..10]); // window
    api::return_value(ReturnFlags::empty(), &out);
}

/// checks whether a probe is whitelisted
///
/// returns: `bool whitelisted`
fn is_probe_whitelisted() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&input[12..32]);

    let mut wl = [0u8; 1];
    sget(&probe_whitelist_key(&probe), &mut wl);

    let mut out = [0u8; 32];
    out[31] = wl[0];
    api::return_value(ReturnFlags::empty(), &out);
}

/// records probe report: hash (32 bytes) + status (1 byte)
/// status codes: 0-127 healthy, 128-255 errors
///
/// args: (address pylon, bytes32 reportHash, uint8 statusCode)
/// returns: `uint32 window`
fn report_probe_data() {
    let mut input = [0u8; 96]; // 3 slots
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);
    
    let mut report_hash = [0u8; 32];
    report_hash.copy_from_slice(&input[36..68]); // slot 1
    
    let status_code = input[95]; // slot 2
    
    // reject 255 sentinel value
    if status_code == 255 {
        api::return_value(ReturnFlags::REVERT, b"invalid status 255");
    }

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut wl = [0u8; 1];
    sget(&probe_whitelist_key(&caller), &mut wl);
    if wl[0] == 0 {
        api::return_value(ReturnFlags::REVERT, b"probe not whitelisted");
    }

    let mut pylon_level = [0u8; 1];
    sget(&pylon_level_key(&pylon), &mut pylon_level);
    if pylon_level[0] == 0 {
        api::return_value(ReturnFlags::REVERT, b"invalid pylon");
    }

    let mut now32 = [0u8; 32];
    api::now(&mut now32);
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&now32[..8]);
    let now = u64::from_le_bytes(lo);
    let window = (now / REPORT_INTERVAL) as u32;

    // enforce one report per probe per window
    let mut reported = [0u8; 1];
    sget(&probe_report_key(&pylon, window, &caller), &mut reported);
    if reported[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already reported");
    }
    
    // store hash and status (33 bytes total)
    let mut report_data = [0u8; 33];
    report_data[0..32].copy_from_slice(&report_hash);
    report_data[32] = status_code;
    sset(&probe_report_key(&pylon, window, &caller), &report_data);

    // simplified window data: [count, healthy_count, degraded_count, error_count]
    let mut wdata = [0u8; 4];
    sget(&probe_window_key(&pylon, window), &mut wdata);

    wdata[0] = wdata[0].saturating_add(1); // total count
    
    if status_code < 128 {
        wdata[1] = wdata[1].saturating_add(1); // healthy count
    } else if status_code < 200 {
        wdata[2] = wdata[2].saturating_add(1); // degraded count
    } else {
        wdata[3] = wdata[3].saturating_add(1); // error count
    }
    
    sset(&probe_window_key(&pylon, window), &wdata);

    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&window.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &out);
}

/// finalizes window with 2/3 consensus requirement
///
/// returns: `uint8 status`
fn finalize_window() {
    let mut input = [0u8; 64]; // 2 slots
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);
    let window = u32::from_be_bytes([input[60], input[61], input[62], input[63]]);

    let mut now32 = [0u8; 32];
    api::now(&mut now32);
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&now32[..8]);
    let now = u64::from_le_bytes(lo);
    let current_window = (now / REPORT_INTERVAL) as u32;

    if window >= current_window {
        api::return_value(ReturnFlags::REVERT, b"window not complete");
    }

    // prevent duplicate finalization
    let mut fin = [0u8; 1];
    sget(&window_finalized_key(&pylon, window), &mut fin);
    if fin[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already finalized");
    }

    let mut wdata = [0u8; 4];
    sget(&probe_window_key(&pylon, window), &mut wdata);

    let total_count = wdata[0];
    let healthy_count = wdata[1];
    let degraded_count = wdata[2];
    let _error_count = wdata[3];

    // mark as insufficient data if not enough probes
    if total_count < MIN_PROBES_FOR_CONSENSUS {
        sset(&pylon_status_key(&pylon), &[2u8]); // insufficient data
        sset(&window_finalized_key(&pylon, window), &[1u8]);
        let mut out = [0u8; 32];
        out[31] = 2;
        api::return_value(ReturnFlags::empty(), &out);
    }

    // 2/3 consensus for status determination
    let consensus_threshold = (total_count * 2) / 3;
    
    let status = if healthy_count >= consensus_threshold {
        0u8 // healthy
    } else if (healthy_count + degraded_count) >= consensus_threshold {
        1u8 // degraded (mixed results but mostly reachable)
    } else {
        128u8 // offline/error (majority reporting errors)
    };

    sset(&pylon_status_key(&pylon), &[status]);

    // store simple metrics: status, counts, window
    let mut metrics = [0u8; 8];
    metrics[0] = status;
    metrics[1] = total_count;
    metrics[2] = healthy_count;
    metrics[3] = degraded_count;
    metrics[4..8].copy_from_slice(&window.to_le_bytes());
    
    sset(&pylon_metrics_key(&pylon), &metrics);          // store metrics
    sset(&probe_window_key(&pylon, window), &[0u8; 4]);  // clear accumulator
    sset(&window_finalized_key(&pylon, window), &[1u8]); // mark finalized

    let mut out = [0u8; 32];
    out[31] = status;
    api::return_value(ReturnFlags::empty(), &out);
}

/// vote weight calculation for governance (equal weights across ranks 5..9)
fn calculate_vote_weight(level: u8) -> u8 {
    match level {
        5..=9 => 1,
        _ => 0,
    }
}

#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

use uapi::{HostFn, HostFnImpl as api, ReturnFlags, StorageFlags};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp");
        core::hint::unreachable_unchecked();
    }
}

// minimal bump allocator on a static buffer (for `alloc`)
mod alloc_support {
    use core::{
        alloc::{GlobalAlloc, Layout},
        sync::atomic::{AtomicUsize, Ordering},
    };

    pub struct BumpAllocator {
        offset: AtomicUsize,
    }

    const HEAP_SIZE: usize = 64 * 1024; // 64 KiB static heap; fine for now.

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
                    Ok(_) => return unsafe { HEAP.as_mut_ptr().add(aligned) },
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

// tiny adapters for new uapi storage signatures 
#[inline(always)]
fn sset(key: &[u8], value: &[u8]) {
    // ignore returned size of previous value
    let _ = api::set_storage(StorageFlags::empty(), key, value);
}

#[inline(always)]
fn sget(key: &[u8], out: &mut [u8]) {
    // leave `out` zeroed if the key is missing or shorter than `out`
    let mut slice = &mut out[..];
    let _ = api::get_storage(StorageFlags::empty(), key, &mut slice);
}

// storage key prefixes
const PYLON_LEVEL_PREFIX: u8 = 1;
const NETWORK_COUNT_KEY: [u8; 32] = [2u8; 32];
const NETWORK_PREFIX: u8 = 3;
const PYLON_PREFIX: u8 = 4;
const DNS_PREFIX: u8 = 5;
const ORG_PREFIX: u8 = 6;
const PYLON_ORG_PREFIX: u8 = 7;
const DNS_CONTROLLER_PREFIX: u8 = 8;
const PROPOSAL_PREFIX: u8 = 9;
const PROPOSAL_COUNT_KEY: [u8; 32] = [10u8; 32];
const VOTE_PREFIX: u8 = 11;
const VOTE_WEIGHT_PREFIX: u8 = 12;
const PROBE_WINDOW_PREFIX: u8 = 13;
const PROBE_REPORT_PREFIX: u8 = 14;
const PYLON_STATUS_PREFIX: u8 = 15;
const PROPOSAL_DATA_PREFIX: u8 = 16;
const PROBE_WHITELIST_PREFIX: u8 = 17;
const PYLON_METRICS_PREFIX: u8 = 18;
const REPORT_INTERVAL: u64 = 300;
const DEGRADATION_THRESHOLD: u8 = 95;
const MIN_PROBES_FOR_CONSENSUS: u8 = 3;

// storage key generators
fn pylon_level_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_LEVEL_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

fn network_key(id: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = NETWORK_PREFIX;
    key[1..5].copy_from_slice(&id.to_le_bytes());
    key
}

fn pylon_key(network_id: u32, pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_PREFIX;
    key[1..5].copy_from_slice(&network_id.to_le_bytes());
    key[5..25].copy_from_slice(pylon);
    key
}

fn dns_key(network_id: u32, org_id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = DNS_PREFIX;
    key[1..5].copy_from_slice(&network_id.to_le_bytes());
    key[5] = org_id;
    key
}

fn org_key(org_id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = ORG_PREFIX;
    key[1] = org_id;
    key
}

fn pylon_org_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_ORG_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

fn dns_controller_key(org_id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = DNS_CONTROLLER_PREFIX;
    key[1] = org_id;
    key
}

fn proposal_key(id: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROPOSAL_PREFIX;
    key[1..5].copy_from_slice(&id.to_le_bytes());
    key
}

fn proposal_data_key(id: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROPOSAL_DATA_PREFIX;
    key[1..5].copy_from_slice(&id.to_le_bytes());
    key
}

fn vote_key(proposal_id: u32, voter: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = VOTE_PREFIX;
    key[1..5].copy_from_slice(&proposal_id.to_le_bytes());
    key[5..25].copy_from_slice(voter);
    key
}

fn vote_weight_key(proposal_id: u32, support: bool) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = VOTE_WEIGHT_PREFIX;
    key[1..5].copy_from_slice(&proposal_id.to_le_bytes());
    key[5] = support as u8;
    key
}

fn probe_window_key(pylon: &[u8; 20], window: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROBE_WINDOW_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key[21..25].copy_from_slice(&window.to_le_bytes());
    key
}

fn probe_report_key(pylon: &[u8; 20], window: u32, probe: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROBE_REPORT_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key[21..25].copy_from_slice(&window.to_le_bytes());
    key[25..27].copy_from_slice(&probe[0..2]);
    key
}

fn pylon_status_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_STATUS_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

fn probe_whitelist_key(probe: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PROBE_WHITELIST_PREFIX;
    key[1..21].copy_from_slice(probe);
    key
}

fn pylon_metrics_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_METRICS_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
    sset(&org_key(1), b"IBP");
    sset(&org_key(2), b"Dotters");
    sset(&NETWORK_COUNT_KEY, &0u32.to_le_bytes());
    sset(&PROPOSAL_COUNT_KEY, &0u32.to_le_bytes());
}

#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
    let mut selector = [0u8; 4];
    api::call_data_copy(&mut selector, 0);

    match u32::from_be_bytes(selector) {
        0xd09de08a => create_network(),
        0xec7dbaa5 => set_network_dns(),
        0x42c9a3f3 => add_pylon(),
        0xb2d1b31f => remove_pylon(),
        0xb9b0f66f => set_pylon_org(),
        0xfcdae25a => set_pylon_level(),
        0x1f9840a8 => execute_set_pylon_level(),
        0xae169a50 => execute_set_pylon_org(),
        0x73cf575a => set_dns_controller(),
        0xa8c62e76 => get_dns_controller(),
        0xb2bdda30 => execute_set_dns_controller(),
        0x3af32abf => whitelist_probe(),
        0xc19d93fb => revoke_probe(),
        0x9a8a0592 => execute_whitelist_probe(),
        0xd892cd12 => execute_revoke_probe(),
        0xda35a26f => propose(),
        0x15373e3d => vote(),
        0xece40cc1 => execute_proposal(),
        0xc5958af9 => get_network_info(),
        0x957888b7 => get_network_count(),
        0x013cf08b => get_proposal(),
        0x609ff1bd => get_pylon_level(),
        0xa776d498 => get_pylon_status(),
        0x7a9e5e4b => get_pylon_metrics(),
        0x2e46b05d => is_probe_whitelisted(),
        0x8f32d59b => report_probe_data(),
        0x4e487b71 => finalize_window(),
        _ => api::return_value(ReturnFlags::REVERT, &[]),
    }
}

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

    count += 1;
    let network_id = count;

    sset(&NETWORK_COUNT_KEY, &count.to_le_bytes());
    sset(&network_key(network_id), &level);
    sset(&pylon_key(network_id, &caller), &[1u8]);

    let mut output = [0u8; 32];
    output[28..32].copy_from_slice(&network_id.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &output);
}

fn set_network_dns() {
    let mut input = [0u8; 96];
    api::call_data_copy(&mut input, 4);

    let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
    let org_id = input[63];
    let enabled = input[95] != 0;

    if org_id != 1 && org_id != 2 {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
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

fn add_pylon() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
    let mut new_pylon = [0u8; 20];
    new_pylon.copy_from_slice(&input[44..64]);

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
    sset(&pylon_status_key(&new_pylon), &[0u8]);
    api::return_value(ReturnFlags::empty(), &[]);
}

fn remove_pylon() {
    api::return_value(ReturnFlags::REVERT, b"use governance");
}

fn set_pylon_org() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);
    let org_id = input[63];

    if org_id != 1 && org_id != 2 {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
    }

    create_proposal(2, &pylon, org_id);
}

fn set_pylon_level() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);
    let new_level = input[63];

    if new_level > 7 {
        api::return_value(ReturnFlags::REVERT, b"max level 7");
    }

    create_proposal(1, &pylon, new_level);
}

fn set_dns_controller() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);

    let org_id = input[31];
    let mut controller = [0u8; 20];
    controller.copy_from_slice(&input[44..64]);

    if org_id != 1 && org_id != 2 {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
    }

    create_proposal(3, &controller, org_id);
}

fn whitelist_probe() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&input[12..32]);

    create_proposal(4, &probe, 1);
}

fn revoke_probe() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&input[12..32]);

    create_proposal(5, &probe, 0);
}

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
    count += 1;

    let mut proposal_meta = [0u8; 32];
    proposal_meta[0] = proposal_type;
    proposal_meta[1..21].copy_from_slice(&caller);
    sset(&proposal_key(count), &proposal_meta);

    let mut proposal_data = [0u8; 32];
    proposal_data[0..20].copy_from_slice(target);
    proposal_data[20] = value;
    sset(&proposal_data_key(count), &proposal_data);

    sset(&PROPOSAL_COUNT_KEY, &count.to_le_bytes());

    let mut output = [0u8; 32];
    output[28..32].copy_from_slice(&count.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &output);
}

fn propose() {
    let mut input = [0u8; 64];
    api::call_data_copy(&mut input, 4);
    let proposal_type = input[31];

    match proposal_type {
        1 => set_pylon_level(),
        2 => set_pylon_org(),
        3 => set_dns_controller(),
        4 => whitelist_probe(),
        5 => revoke_probe(),
        _ => api::return_value(ReturnFlags::REVERT, b"invalid type"),
    }
}

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

    let mut existing_vote = [0u8; 1];
    sget(&vote_key(proposal_id, &voter), &mut existing_vote);

    if existing_vote[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already voted");
    }

    let weight = calculate_vote_weight(level[0]);

    sset(&vote_key(proposal_id, &voter), &[support as u8 + 1]);

    let mut tally_bytes = [0u8; 2];
    sget(&vote_weight_key(proposal_id, support), &mut tally_bytes);
    let mut tally = u16::from_le_bytes(tally_bytes);
    tally += weight as u16;
    sset(&vote_weight_key(proposal_id, support), &tally.to_le_bytes());

    let mut output = [0u8; 32];
    output[30..32].copy_from_slice(&tally.to_le_bytes());
    api::return_value(ReturnFlags::empty(), &output);
}

fn execute_proposal() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);

    let mut yes_bytes = [0u8; 2];
    sget(&vote_weight_key(proposal_id, true), &mut yes_bytes);
    let yes_weight = u16::from_le_bytes(yes_bytes);

    let mut no_bytes = [0u8; 2];
    sget(&vote_weight_key(proposal_id, false), &mut no_bytes);
    let no_weight = u16::from_le_bytes(no_bytes);

    let total = yes_weight + no_weight;
    if total == 0 || (yes_weight * 3) < (total * 2) {
        api::return_value(ReturnFlags::REVERT, b"need 2/3 majority");
    }

    let mut proposal_meta = [0u8; 32];
    sget(&proposal_key(proposal_id), &mut proposal_meta);
    let proposal_type = proposal_meta[0];

    match proposal_type {
        1 => execute_set_pylon_level_internal(proposal_id),
        2 => execute_set_pylon_org_internal(proposal_id),
        3 => execute_set_dns_controller_internal(proposal_id),
        4 => execute_whitelist_probe_internal(proposal_id),
        5 => execute_revoke_probe_internal(proposal_id),
        _ => api::return_value(ReturnFlags::REVERT, b"invalid type"),
    }
}

fn execute_set_pylon_level() {
    execute_proposal();
}

fn execute_set_pylon_level_internal(proposal_id: u32) {
    let mut proposal_data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut proposal_data);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&proposal_data[0..20]);
    let new_level = proposal_data[20];

    sset(&pylon_level_key(&pylon), &[new_level]);

    let mut output = [0u8; 32];
    output[31] = 1;
    api::return_value(ReturnFlags::empty(), &output);
}

fn execute_set_pylon_org() {
    execute_proposal();
}

fn execute_set_pylon_org_internal(proposal_id: u32) {
    let mut proposal_data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut proposal_data);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&proposal_data[0..20]);
    let org_id = proposal_data[20];

    sset(&pylon_org_key(&pylon), &[org_id]);

    let mut output = [0u8; 32];
    output[31] = 1;
    api::return_value(ReturnFlags::empty(), &output);
}

fn execute_set_dns_controller() {
    execute_proposal();
}

fn execute_set_dns_controller_internal(proposal_id: u32) {
    let mut proposal_data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut proposal_data);

    let mut controller = [0u8; 20];
    controller.copy_from_slice(&proposal_data[0..20]);
    let org_id = proposal_data[20];

    sset(&dns_controller_key(org_id), &controller);

    let mut output = [0u8; 32];
    output[31] = 1;
    api::return_value(ReturnFlags::empty(), &output);
}

fn execute_whitelist_probe() {
    execute_proposal();
}

fn execute_whitelist_probe_internal(proposal_id: u32) {
    let mut proposal_data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut proposal_data);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&proposal_data[0..20]);

    sset(&probe_whitelist_key(&probe), &[1u8]);

    let mut output = [0u8; 32];
    output[31] = 1;
    api::return_value(ReturnFlags::empty(), &output);
}

fn execute_revoke_probe() {
    execute_proposal();
}

fn execute_revoke_probe_internal(proposal_id: u32) {
    let mut proposal_data = [0u8; 32];
    sget(&proposal_data_key(proposal_id), &mut proposal_data);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&proposal_data[0..20]);

    sset(&probe_whitelist_key(&probe), &[0u8]);

    let mut output = [0u8; 32];
    output[31] = 1;
    api::return_value(ReturnFlags::empty(), &output);
}

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

    let mut output = [0u8; 32];
    output[29] = level_req[0];
    output[30] = ibp_dns[0];
    output[31] = dotters_dns[0];
    api::return_value(ReturnFlags::empty(), &output);
}

fn get_network_count() {
    let mut count_bytes = [0u8; 4];
    sget(&NETWORK_COUNT_KEY, &mut count_bytes);
    let count = u32::from_le_bytes(count_bytes);

    let mut output = [0u8; 32];
    output[28..32].copy_from_slice(&count.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &output);
}

fn get_dns_controller() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let org_id = input[31];

    if org_id != 1 && org_id != 2 {
        api::return_value(ReturnFlags::REVERT, b"invalid org");
    }

    let mut controller = [0u8; 20];
    sget(&dns_controller_key(org_id), &mut controller);

    let mut output = [0u8; 32];
    output[12..32].copy_from_slice(&controller);
    api::return_value(ReturnFlags::empty(), &output);
}

fn get_proposal() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);

    let mut proposal_data = [0u8; 32];
    sget(&proposal_key(proposal_id), &mut proposal_data);

    api::return_value(ReturnFlags::empty(), &proposal_data);
}

fn get_pylon_level() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);

    let mut level = [0u8; 1];
    sget(&pylon_level_key(&pylon), &mut level);

    let mut output = [0u8; 32];
    output[31] = level[0];
    api::return_value(ReturnFlags::empty(), &output);
}

fn get_pylon_status() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);

    let mut status = [0u8; 1];
    sget(&pylon_status_key(&pylon), &mut status);

    let mut output = [0u8; 32];
    output[31] = status[0];
    api::return_value(ReturnFlags::empty(), &output);
}

fn get_pylon_metrics() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);

    let mut metrics = [0u8; 16];
    sget(&pylon_metrics_key(&pylon), &mut metrics);

    let mut output = [0u8; 32];
    output[16..32].copy_from_slice(&metrics);
    api::return_value(ReturnFlags::empty(), &output);
}

fn is_probe_whitelisted() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);

    let mut probe = [0u8; 20];
    probe.copy_from_slice(&input[12..32]);

    let mut whitelisted = [0u8; 1];
    sget(&probe_whitelist_key(&probe), &mut whitelisted);

    let mut output = [0u8; 32];
    output[31] = whitelisted[0];
    api::return_value(ReturnFlags::empty(), &output);
}

fn report_probe_data() {
    let mut input = [0u8; 68];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);

    let regions = u32::from_be_bytes([input[32], input[33], input[34], input[35]]);
    let latency = u16::from_be_bytes([input[36], input[37]]);
    let uptime = input[67];

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut whitelisted = [0u8; 1];
    sget(&probe_whitelist_key(&caller), &mut whitelisted);

    if whitelisted[0] == 0 {
        api::return_value(ReturnFlags::REVERT, b"probe not whitelisted");
    }

    let mut pylon_level = [0u8; 1];
    sget(&pylon_level_key(&pylon), &mut pylon_level);

    if pylon_level[0] == 0 {
        api::return_value(ReturnFlags::REVERT, b"invalid pylon");
    }

    let mut current_time = [0u8; 32];
    api::now(&mut current_time);
    let mut time_bytes = [0u8; 8];
    time_bytes.copy_from_slice(&current_time[..8]);
    let current_timestamp = u64::from_le_bytes(time_bytes);
    let window = (current_timestamp / REPORT_INTERVAL) as u32;

    let mut reported = [0u8; 1];
    sget(&probe_report_key(&pylon, window, &caller), &mut reported);

    if reported[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already reported");
    }

    sset(&probe_report_key(&pylon, window, &caller), &[1u8]);

    let mut window_data = [0u8; 12];
    sget(&probe_window_key(&pylon, window), &mut window_data);

    let mut report_count = window_data[0];
    let mut total_uptime = u16::from_le_bytes([window_data[1], window_data[2]]);
    let mut total_latency =
        u32::from_le_bytes([window_data[3], window_data[4], window_data[5], window_data[6]]);
    let mut regions_coverage =
        u32::from_le_bytes([window_data[7], window_data[8], window_data[9], window_data[10]]);

    report_count += 1;
    total_uptime += uptime as u16;
    total_latency += latency as u32;
    regions_coverage |= regions;

    window_data[0] = report_count;
    window_data[1..3].copy_from_slice(&total_uptime.to_le_bytes());
    window_data[3..7].copy_from_slice(&total_latency.to_le_bytes());
    window_data[7..11].copy_from_slice(&regions_coverage.to_le_bytes());

    sset(&probe_window_key(&pylon, window), &window_data);

    let mut output = [0u8; 32];
    output[28..32].copy_from_slice(&window.to_be_bytes());
    api::return_value(ReturnFlags::empty(), &output);
}

fn finalize_window() {
    let mut input = [0u8; 36];
    api::call_data_copy(&mut input, 4);

    let mut pylon = [0u8; 20];
    pylon.copy_from_slice(&input[12..32]);
    let window = u32::from_be_bytes([input[32], input[33], input[34], input[35]]);

    let mut current_time = [0u8; 32];
    api::now(&mut current_time);
    let mut time_bytes = [0u8; 8];
    time_bytes.copy_from_slice(&current_time[..8]);
    let current_timestamp = u64::from_le_bytes(time_bytes);
    let current_window = (current_timestamp / REPORT_INTERVAL) as u32;

    if window >= current_window {
        api::return_value(ReturnFlags::REVERT, b"window not complete");
    }

    let mut window_data = [0u8; 12];
    sget(&probe_window_key(&pylon, window), &mut window_data);

    let report_count = window_data[0];

    if report_count < MIN_PROBES_FOR_CONSENSUS {
        sset(&pylon_status_key(&pylon), &[2u8]);
        api::return_value(ReturnFlags::empty(), &[2u8]);
    }

    let total_uptime = u16::from_le_bytes([window_data[1], window_data[2]]);
    let total_latency =
        u32::from_le_bytes([window_data[3], window_data[4], window_data[5], window_data[6]]);
    let regions =
        u32::from_le_bytes([window_data[7], window_data[8], window_data[9], window_data[10]]);

    let avg_uptime = (total_uptime / report_count as u16) as u8;
    let avg_latency = (total_latency / report_count as u32) as u16;

    let status = if avg_uptime < DEGRADATION_THRESHOLD { 1u8 } else { 0u8 };

    sset(&pylon_status_key(&pylon), &[status]);

    let mut metrics = [0u8; 16];
    metrics[0] = avg_uptime;
    metrics[1..3].copy_from_slice(&avg_latency.to_le_bytes());
    metrics[3..7].copy_from_slice(&regions.to_le_bytes());
    metrics[7..11].copy_from_slice(&window.to_le_bytes());
    metrics[11] = report_count;

    sset(&pylon_metrics_key(&pylon), &metrics);

    sset(&probe_window_key(&pylon, window), &[0u8; 12]);

    let mut output = [0u8; 32];
    output[31] = status;
    api::return_value(ReturnFlags::empty(), &output);
}

// vote weight based on rank level
fn calculate_vote_weight(level: u8) -> u8 {
    match level {
        5 => 1,
        6 => 1,
        7 => 1,
        8 => 1,
        9 => 1,
        _ => 0,
    }
}

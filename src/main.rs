#![feature(alloc_error_handler)]
#![no_main]
#![no_std]
#![allow(static_mut_refs)]

use uapi::{CallFlags, HostFn, HostFnImpl as api, ReturnFlags, StorageFlags};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp");
        core::hint::unreachable_unchecked();
    }
}

// ---- minimal bump allocator on a static buffer (required by `alloc`) ----
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

// ---- tiny adapters for new uapi storage signatures ----
#[inline(always)]
fn sset(key: &[u8], value: &[u8]) {
    let _ = api::set_storage(StorageFlags::empty(), key, value);
}
#[inline(always)]
fn sget(key: &[u8], out: &mut [u8]) {
    let mut slice = &mut out[..];
    let _ = api::get_storage(StorageFlags::empty(), key, &mut slice);
}

// ---- shared and controller-specific storage keys ----

// shared with implementation (controller must read levels)
// keep this prefix identical in both contracts.
const PYLON_LEVEL_PREFIX: u8 = 0x10;

/// returns the storage key for a pylon's level (shared between controller and implementation)
fn pylon_level_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_LEVEL_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

// controller-only keys: use distinct high-value markers to avoid any collision
const IMPLEMENTATION_KEY: [u8; 32] = [0xA1; 32];
const PENDING_IMPL_KEY: [u8; 32] = [0xA2; 32];
const UPGRADE_PROPOSAL_KEY: [u8; 32] = [0xA3; 32];
const UPGRADE_YES_WEIGHT_KEY: [u8; 32] = [0xA4; 32];
const UPGRADE_NO_WEIGHT_KEY: [u8; 32] = [0xA5; 32];
const TEMPLAR_KEY: [u8; 32] = [0xA7; 32];
const UPGRADE_VOTE_PREFIX: u8 = 0xA6;

/// generates per-voter key for controller upgrade votes
fn upgrade_vote_key(voter: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = UPGRADE_VOTE_PREFIX;
    key[1..21].copy_from_slice(voter);
    key
}

/// computes the first 4 bytes of keccak(signature) at runtime
#[inline(always)]
fn sel(signature: &str) -> [u8; 4] {
    let mut h = [0u8; 32];
    api::hash_keccak_256(signature.as_bytes(), &mut h);
    [h[0], h[1], h[2], h[3]]
}

/// initializes proxy with implementation address and deployer as templar
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
    // abi: constructor(address implementation)
    let mut implementation = [0u8; 20];
    // address is the last 20 bytes of the first 32-byte slot
    api::call_data_copy(&mut implementation, 16);
    sset(&IMPLEMENTATION_KEY, &implementation);

    let mut deployer = [0u8; 20];
    api::caller(&mut deployer);
    sset(&TEMPLAR_KEY, &deployer);
}

/// routes calls to proxy functions or delegates to implementation
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
    let mut selector = [0u8; 4];
    api::call_data_copy(&mut selector, 0);

    // compute proxy selectors on the fly to avoid accidental collisions
    let s_propose_upgrade = sel("proposeUpgrade(address)");
    let s_vote_upgrade = sel("voteUpgrade(bool)");
    let s_execute_upgrade = sel("executeUpgrade()");
    let s_get_implementation = sel("getImplementation()");
    let s_get_pending_upgrade = sel("getPendingUpgrade()");
    let s_remove_templar = sel("removeTemplar()");

    match selector {
        x if x == s_propose_upgrade => propose_upgrade(),
        x if x == s_vote_upgrade => vote_upgrade(),
        x if x == s_execute_upgrade => execute_upgrade(),
        x if x == s_get_implementation => get_implementation(),
        x if x == s_get_pending_upgrade => get_pending_upgrade(),
        x if x == s_remove_templar => remove_templar(),
        _ => delegate_to_implementation(),
    }
}

/// proposes a new implementation for upgrade and clears previous tallies
///
/// expects: `proposeUpgrade(address)`
/// effects: sets pending implementation, resets tallies, records proposal timestamp
fn propose_upgrade() {
    let mut new_impl = [0u8; 20];
    // address is at slot #0 => bytes [16..36) after selector
    api::call_data_copy(&mut new_impl, 16);

    // reset tallies and store pending impl
    sset(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
    sset(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);
    sset(&PENDING_IMPL_KEY, &new_impl);

    // record proposal time (little-endian u64 in first 8 bytes)
    let mut timestamp = [0u8; 32];
    api::now(&mut timestamp);
    sset(&UPGRADE_PROPOSAL_KEY, &timestamp[..8]);

    api::return_value(ReturnFlags::empty(), &[]);
}

/// casts a weighted vote for or against the pending upgrade (equal weights 5..7 = 1)
///
/// expects: `voteUpgrade(bool)`
/// reverts if: no pending upgrade or duplicate vote or unauthorized
fn vote_upgrade() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);
    let support = input[31] != 0;

    let mut pending = [0u8; 20];
    sget(&PENDING_IMPL_KEY, &mut pending);
    if pending == [0u8; 20] {
        api::return_value(ReturnFlags::REVERT, b"no pending upgrade");
    }

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    // prevent duplicate vote
    let mut existing_vote = [0u8; 1];
    sget(&upgrade_vote_key(&caller), &mut existing_vote);
    if existing_vote[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already voted");
    }

    // equal weight across ranks 5..7
    let weight = get_voter_weight(&caller);
    if weight == 0 {
        api::return_value(ReturnFlags::REVERT, b"not authorized");
    }

    sset(&upgrade_vote_key(&caller), &[support as u8 + 1]);

    // update tally
    let key = if support { UPGRADE_YES_WEIGHT_KEY } else { UPGRADE_NO_WEIGHT_KEY };
    let mut tally_bytes = [0u8; 2];
    sget(&key, &mut tally_bytes);
    let mut tally = u16::from_le_bytes(tally_bytes);
    tally = tally.saturating_add(weight as u16);
    sset(&key, &tally.to_le_bytes());

    let mut out = [0u8; 32];
    out[30..32].copy_from_slice(&tally.to_le_bytes());
    api::return_value(ReturnFlags::empty(), &out);
}

/// executes the upgrade if a 2/3 majority is met and timelock has passed (templar can bypass delay)
///
/// expects: `executeUpgrade()`
/// effects: sets implementation and clears pending+tallies on success
fn execute_upgrade() {
    let mut pending = [0u8; 20];
    sget(&PENDING_IMPL_KEY, &mut pending);
    if pending == [0u8; 20] {
        api::return_value(ReturnFlags::REVERT, b"no pending upgrade");
    }

    let mut yes_bytes = [0u8; 2];
    sget(&UPGRADE_YES_WEIGHT_KEY, &mut yes_bytes);
    let yes = u16::from_le_bytes(yes_bytes);

    let mut no_bytes = [0u8; 2];
    sget(&UPGRADE_NO_WEIGHT_KEY, &mut no_bytes);
    let no = u16::from_le_bytes(no_bytes);

    let total = yes + no;
    if total == 0 || (yes * 3) < (total * 2) {
        api::return_value(ReturnFlags::REVERT, b"need 2/3 majority");
    }

    // templar can bypass timelock once
    let mut templar = [0u8; 20];
    sget(&TEMPLAR_KEY, &mut templar);

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    if templar != [0u8; 20] && caller == templar {
        sset(&IMPLEMENTATION_KEY, &pending);
        sset(&PENDING_IMPL_KEY, &[0u8; 20]);
        sset(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
        sset(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);
        api::return_value(ReturnFlags::empty(), &[1u8]);
    }

    let mut ts = [0u8; 8];
    sget(&UPGRADE_PROPOSAL_KEY, &mut ts);
    let proposed = u64::from_le_bytes(ts);

    let mut now32 = [0u8; 32];
    api::now(&mut now32);
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&now32[..8]);
    let now = u64::from_le_bytes(lo);

    // 48h delay
    if now < proposed.saturating_add(172_800) {
        api::return_value(ReturnFlags::REVERT, b"48h delay required");
    }

    sset(&IMPLEMENTATION_KEY, &pending);
    sset(&PENDING_IMPL_KEY, &[0u8; 20]);
    sset(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
    sset(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

/// permanently removes the templar privilege
fn remove_templar() {
    let mut templar = [0u8; 20];
    sget(&TEMPLAR_KEY, &mut templar);

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    if caller != templar {
        api::return_value(ReturnFlags::REVERT, b"not templar");
    }

    sset(&TEMPLAR_KEY, &[0u8; 20]);
    api::return_value(ReturnFlags::empty(), &[]);
}

/// returns the current implementation address
fn get_implementation() {
    let mut impl_addr = [0u8; 20];
    sget(&IMPLEMENTATION_KEY, &mut impl_addr);

    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&impl_addr);
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns the pending implementation address (if any)
fn get_pending_upgrade() {
    let mut pending = [0u8; 20];
    sget(&PENDING_IMPL_KEY, &mut pending);

    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&pending);
    api::return_value(ReturnFlags::empty(), &out);
}

/// returns the voting weight for an address based on IBP level (equal weight for 5..7)
fn get_voter_weight(voter: &[u8; 20]) -> u8 {
    let mut level = [0u8; 1];
    sget(&pylon_level_key(voter), &mut level);

    match level[0] {
        5 | 6 | 7 => 1,
        _ => 0,
    }
}

/// delegates unrecognized calls to the implementation in the controller context
fn delegate_to_implementation() {
    let mut implementation = [0u8; 20];
    sget(&IMPLEMENTATION_KEY, &mut implementation);

    let data_len = api::call_data_size() as usize;
    const MAX_DATA: usize = 8192;
    if data_len > MAX_DATA {
        api::return_value(ReturnFlags::REVERT, b"data too large");
    }

    let mut data_buf = [0u8; MAX_DATA];
    let data = &mut data_buf[..data_len];
    api::call_data_copy(data, 0);

    let mut out_buf = [0u8; MAX_DATA];
    let mut out = &mut out_buf[..];

    match api::delegate_call(
        CallFlags::empty(),
        &implementation,
        api::gas_limit() * 9 / 10,
        0,
        &[0u8; 32],
        data,
        Some(&mut out),
    ) {
        Ok(()) => api::return_value(ReturnFlags::empty(), out),
        Err(_) => api::return_value(ReturnFlags::REVERT, &[]),
    }
}

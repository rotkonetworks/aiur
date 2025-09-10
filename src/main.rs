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

// NOTE: sget/sset use little-endian to_le_bytes()
// while ABI return values big endian to_be_bytes()
// and EventData big endian to_be_bytes()

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
const UPGRADE_ID_KEY: [u8; 32] = [0xA8; 32];

/// generates per-voter key for controller upgrade votes (versioned by proposal ID)
fn upgrade_vote_key(upgrade_id: u32, voter: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = UPGRADE_VOTE_PREFIX;
   key[1..5].copy_from_slice(&upgrade_id.to_le_bytes());
   key[5..25].copy_from_slice(voter);
   key
}

/// computes the first 4 bytes of keccak(signature) at runtime
#[inline(always)]
fn sel(signature: &str) -> [u8; 4] {
   let mut h = [0u8; 32];
   api::hash_keccak_256(signature.as_bytes(), &mut h);
   [h[0], h[1], h[2], h[3]]
}

// ---- evm event emission helpers ----

/// emits UpgradeProposed(address indexed proposer, address indexed newImplementation, uint256 timestamp)
fn emit_upgrade_proposed(proposer: &[u8; 20], new_impl: &[u8; 20]) {
   let mut topic0 = [0u8; 32]; // event signature - FULL hash
   api::hash_keccak_256(b"UpgradeProposed(address,address,uint256)", &mut topic0);

   let mut topic1 = [0u8; 32]; // proposer (indexed)
   topic1[12..32].copy_from_slice(proposer);

   let mut topic2 = [0u8; 32]; // newImplementation (indexed)
   topic2[12..32].copy_from_slice(new_impl);

   let mut data = [0u8; 32]; // timestamp
   api::now(&mut data);

   let topics = [topic0, topic1, topic2];
   api::deposit_event(&topics, &data);
}

/// emits UpgradeVoted(address indexed voter, bool support, uint16 weight)
fn emit_upgrade_voted(voter: &[u8; 20], support: bool, weight: u16) {
   let mut topic0 = [0u8; 32]; // event signature - FULL hash
   api::hash_keccak_256(b"UpgradeVoted(address,bool,uint16)", &mut topic0);

   let mut topic1 = [0u8; 32]; // voter (indexed)
   topic1[12..32].copy_from_slice(voter);

   let mut data = [0u8; 64];
   data[31] = support as u8;
   data[62..64].copy_from_slice(&weight.to_be_bytes());

   let topics = [topic0, topic1];
   api::deposit_event(&topics, &data);
}

/// emits UpgradeExecuted(address indexed oldImplementation, address indexed newImplementation)
fn emit_upgrade_executed(old_impl: &[u8; 20], new_impl: &[u8; 20]) {
   let mut topic0 = [0u8; 32]; // event signature - FULL hash
   api::hash_keccak_256(b"UpgradeExecuted(address,address)", &mut topic0);

   let mut topic1 = [0u8; 32]; // oldImplementation (indexed)
   topic1[12..32].copy_from_slice(old_impl);

   let mut topic2 = [0u8; 32]; // newImplementation (indexed)
   topic2[12..32].copy_from_slice(new_impl);

   let topics = [topic0, topic1, topic2];
   api::deposit_event(&topics, &[]);
}

/// emits TemplarRemoved(address indexed templar)
fn emit_templar_removed(templar: &[u8; 20]) {
   let mut topic0 = [0u8; 32]; // event signature - FULL hash
   api::hash_keccak_256(b"TemplarRemoved(address)", &mut topic0);

   let mut topic1 = [0u8; 32];
   topic1[12..32].copy_from_slice(templar);

   let topics = [topic0, topic1];
   api::deposit_event(&topics, &[]);
}

/// initializes proxy with implementation address and deployer as templar
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
   let mut deployer = [0u8; 20];
   api::caller(&mut deployer);
   sset(&TEMPLAR_KEY, &deployer);
   
   // Check if implementation address is provided in calldata (EOF-init)
   let n = api::call_data_size() as usize;
   if n >= 20 {
       let mut implementation = [0u8; 20];
       api::call_data_copy(&mut implementation, (n - 20) as u32);
       sset(&IMPLEMENTATION_KEY, &implementation);
   } else {
       // Two-step init: deploy with empty implementation
       sset(&IMPLEMENTATION_KEY, &[0u8; 20]);
   }
}

/// initializes the controller with an implementation address
fn initialize() {
   let mut implementation = [0u8; 20];
   api::call_data_copy(&mut implementation, 16); // address at bytes 16-36
   
   // Reject zero address
   if implementation == [0u8; 20] {
       api::return_value(ReturnFlags::REVERT, b"zero implementation");
   }
   
   // Check if already initialized
   let mut current = [0u8; 20];
   sget(&IMPLEMENTATION_KEY, &mut current);
   if current != [0u8; 20] {
       api::return_value(ReturnFlags::REVERT, b"already initialized");
   }
   
   // Check if implementation has code
   let size = api::code_size(&implementation);
   if size == 0 {
       api::return_value(ReturnFlags::REVERT, b"no code at implementation");
   }
   
   sset(&IMPLEMENTATION_KEY, &implementation);
   api::return_value(ReturnFlags::empty(), &[]);
}

/// routes calls to proxy functions or delegates to implementation
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
   let mut selector = [0u8; 4];
   api::call_data_copy(&mut selector, 0);

   // compute proxy selectors on the fly to avoid accidental collisions
   let s_initialize = sel("initialize(address)");
   let s_propose_upgrade = sel("proposeUpgrade(address)");
   let s_vote_upgrade = sel("voteUpgrade(bool)");
   let s_execute_upgrade = sel("executeUpgrade()");
   let s_get_implementation = sel("getImplementation()");
   let s_get_pending_upgrade = sel("getPendingUpgrade()");
   let s_remove_templar = sel("removeTemplar()");

   match selector {
       x if x == s_initialize => initialize(),
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

   // reject zero address
   if new_impl == [0u8; 20] {
       api::return_value(ReturnFlags::REVERT, b"zero implementation");
   }
   
   // get current implementation
   let mut current_impl = [0u8; 20];
   sget(&IMPLEMENTATION_KEY, &mut current_impl);
   
   // reject if same as current
   if new_impl == current_impl {
       api::return_value(ReturnFlags::REVERT, b"same as current");
   }

   let mut caller = [0u8; 20];
   api::caller(&mut caller);

   // increment upgrade ID for new proposal
   let mut upgrade_id_bytes = [0u8; 4];
   sget(&UPGRADE_ID_KEY, &mut upgrade_id_bytes);
   let mut upgrade_id = u32::from_le_bytes(upgrade_id_bytes);
   upgrade_id = upgrade_id.saturating_add(1);
   sset(&UPGRADE_ID_KEY, &upgrade_id.to_le_bytes());

   // reset tallies and store pending impl
   sset(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
   sset(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);
   sset(&PENDING_IMPL_KEY, &new_impl);

   // record proposal time (little-endian u64 in first 8 bytes)
   let mut timestamp = [0u8; 32];
   api::now(&mut timestamp);
   sset(&UPGRADE_PROPOSAL_KEY, &timestamp[..8]);

   emit_upgrade_proposed(&caller, &new_impl);
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

   // get current upgrade ID
   let mut upgrade_id_bytes = [0u8; 4];
   sget(&UPGRADE_ID_KEY, &mut upgrade_id_bytes);
   let upgrade_id = u32::from_le_bytes(upgrade_id_bytes);
   if upgrade_id == 0 {
       api::return_value(ReturnFlags::REVERT, b"no active proposal");
   }

   let mut caller = [0u8; 20];
   api::caller(&mut caller);

   // prevent duplicate vote (versioned by upgrade ID)
   let mut existing_vote = [0u8; 1];
   sget(&upgrade_vote_key(upgrade_id, &caller), &mut existing_vote);
   if existing_vote[0] != 0 {
       api::return_value(ReturnFlags::REVERT, b"already voted");
   }

   // equal weight across ranks 5..7
   let weight = get_voter_weight(&caller);
   if weight == 0 {
       api::return_value(ReturnFlags::REVERT, b"not authorized");
   }

   sset(&upgrade_vote_key(upgrade_id, &caller), &[support as u8 + 1]);

   // update tally
   let key = if support { UPGRADE_YES_WEIGHT_KEY } else { UPGRADE_NO_WEIGHT_KEY };
   let mut tally_bytes = [0u8; 2];
   sget(&key, &mut tally_bytes);
   let mut tally = u16::from_le_bytes(tally_bytes);
   tally = tally.saturating_add(weight as u16);
   sset(&key, &tally.to_le_bytes());

   emit_upgrade_voted(&caller, support, tally);

   let mut out = [0u8; 32];
   out[30..32].copy_from_slice(&tally.to_be_bytes());
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
   // use ceiling division: (total * 2 + 2) / 3
   let threshold = (total * 2 + 2) / 3;
   if total == 0 || yes < threshold {
       api::return_value(ReturnFlags::REVERT, b"need 2/3 majority");
   }

   // templar can bypass timelock once
   let mut templar = [0u8; 20];
   sget(&TEMPLAR_KEY, &mut templar);

   let mut caller = [0u8; 20];
   api::caller(&mut caller);

   let mut old_impl = [0u8; 20];
   sget(&IMPLEMENTATION_KEY, &mut old_impl);

   if templar != [0u8; 20] && caller == templar {
       sset(&IMPLEMENTATION_KEY, &pending);
       sset(&PENDING_IMPL_KEY, &[0u8; 20]);
       sset(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
       sset(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);
       emit_upgrade_executed(&old_impl, &pending);
       
       // get current upgrade ID to return
       let mut upgrade_id_bytes = [0u8; 4];
       sget(&UPGRADE_ID_KEY, &mut upgrade_id_bytes);
       let upgrade_id = u32::from_le_bytes(upgrade_id_bytes);
       
       let mut out = [0u8; 32];
       out[28..32].copy_from_slice(&upgrade_id.to_be_bytes());
       api::return_value(ReturnFlags::empty(), &out);
   }

   let mut ts = [0u8; 8];
   sget(&UPGRADE_PROPOSAL_KEY, &mut ts);
   let proposed = u64::from_le_bytes(ts);

   let mut now32 = [0u8; 32];
   api::now(&mut now32);
   let mut lo = [0u8; 8];
   lo.copy_from_slice(&now32[..8]);
   let now = u64::from_le_bytes(lo);

   // 48h delay (28800*6s blocks)
   if now < proposed.saturating_add(28_800) {
       api::return_value(ReturnFlags::REVERT, b"48h delay required");
   }

   sset(&IMPLEMENTATION_KEY, &pending);
   sset(&PENDING_IMPL_KEY, &[0u8; 20]);
   sset(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
   sset(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);

   emit_upgrade_executed(&old_impl, &pending);
   
   // get current upgrade ID to return
   let mut upgrade_id_bytes = [0u8; 4];
   sget(&UPGRADE_ID_KEY, &mut upgrade_id_bytes);
   let upgrade_id = u32::from_le_bytes(upgrade_id_bytes);
   
   let mut out = [0u8; 32];
   out[28..32].copy_from_slice(&upgrade_id.to_be_bytes());
   api::return_value(ReturnFlags::empty(), &out);
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
   emit_templar_removed(&templar);
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

   // check if implementation is set
   if implementation == [0u8; 20] {
       api::return_value(ReturnFlags::REVERT, b"no implementation");
   }

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

   // guard against zero gas
   let gas_limit = api::gas_limit();
   if gas_limit == 0 {
       api::return_value(ReturnFlags::REVERT, b"zero gas limit");
   }

   match api::delegate_call(
       CallFlags::empty(),
       &implementation,
       gas_limit * 9 / 10,
       0,
       &[0u8; 32],
       data,
       Some(&mut out),
   ) {
       Ok(()) => api::return_value(ReturnFlags::empty(), out),
       Err(_) => api::return_value(ReturnFlags::REVERT, &[]),
   }
}

#![no_main]
#![no_std]

use uapi::{CallFlags, HostFn, HostFnImpl as api, ReturnFlags};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp");
        core::hint::unreachable_unchecked();
    }
}

// contract terminology:
// PYLON: an IBP member node (has a rank 1-9)
// PROBE: a monitoring node that reports on pylon health
// TEMPLAR: bootstrap role in the proxy contract

// storage keys
const IMPLEMENTATION_KEY: [u8; 32] = [1u8; 32];
const PENDING_IMPL_KEY: [u8; 32] = [2u8; 32];
const UPGRADE_PROPOSAL_KEY: [u8; 32] = [3u8; 32];
const UPGRADE_YES_WEIGHT_KEY: [u8; 32] = [4u8; 32];
const UPGRADE_NO_WEIGHT_KEY: [u8; 32] = [5u8; 32];
const UPGRADE_VOTE_PREFIX: u8 = 6;
const TEMPLAR_KEY: [u8; 32] = [7u8; 32];
const PYLON_LEVEL_PREFIX: u8 = 1;

/// generates storage key for upgrade vote by voter address
fn upgrade_vote_key(voter: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = UPGRADE_VOTE_PREFIX;
    key[1..21].copy_from_slice(voter);
    key
}

/// generates storage key for pylon level
fn pylon_level_key(pylon: &[u8; 20]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = PYLON_LEVEL_PREFIX;
    key[1..21].copy_from_slice(pylon);
    key
}

/// initializes proxy with implementation address and deployer as templar
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
    let mut implementation = [0u8; 20];
    api::call_data_copy(&mut implementation, 0);
    api::set_storage(&IMPLEMENTATION_KEY, &implementation);

    let mut deployer = [0u8; 20];
    api::caller(&mut deployer);
    api::set_storage(&TEMPLAR_KEY, &deployer);
}

/// routes calls to proxy functions or delegates to implementation
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
    let mut selector = [0u8; 4];
    api::call_data_copy(&mut selector, 0);

    match u32::from_be_bytes(selector) {
        0x3659cfe6 => propose_upgrade(),
        0x15373e3d => vote_upgrade(),
        0x4f1ef286 => execute_upgrade(),
        0x5c60da1b => get_implementation(),
        0x8b7e74b4 => get_pending_upgrade(),
        0xf851a440 => remove_templar(),
        _ => delegate_to_implementation(),
    }
}

/// proposes new implementation for upgrade, clears previous votes
fn propose_upgrade() {
    let mut new_impl = [0u8; 20];
    api::call_data_copy(&mut new_impl, 12);

    api::set_storage(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
    api::set_storage(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);
    api::set_storage(&PENDING_IMPL_KEY, &new_impl);

    let mut timestamp = [0u8; 32];
    api::now(&mut timestamp);
    api::set_storage(&UPGRADE_PROPOSAL_KEY, &timestamp[..8]);

    api::return_value(ReturnFlags::empty(), &[]);
}

/// casts weighted vote for or against pending upgrade
fn vote_upgrade() {
    let mut input = [0u8; 32];
    api::call_data_copy(&mut input, 4);
    let support = input[31] != 0;

    let mut pending = [0u8; 20];
    api::get_storage(&PENDING_IMPL_KEY, &mut pending);

    if pending == [0u8; 20] {
        api::return_value(ReturnFlags::REVERT, b"no pending upgrade");
        return;
    }

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    let mut existing_vote = [0u8; 1];
    api::get_storage(&upgrade_vote_key(&caller), &mut existing_vote);

    if existing_vote[0] != 0 {
        api::return_value(ReturnFlags::REVERT, b"already voted");
        return;
    }

    let weight = get_voter_weight(&caller);

    if weight == 0 {
        api::return_value(ReturnFlags::REVERT, b"not authorized");
        return;
    }

    api::set_storage(&upgrade_vote_key(&caller), &[support as u8 + 1]);

    let weight_key = if support { UPGRADE_YES_WEIGHT_KEY } else { UPGRADE_NO_WEIGHT_KEY };
    let mut tally_bytes = [0u8; 2];
    api::get_storage(&weight_key, &mut tally_bytes);
    let mut tally = u16::from_le_bytes(tally_bytes);
    tally += weight as u16;
    api::set_storage(&weight_key, &tally.to_le_bytes());

    let mut output = [0u8; 32];
    output[30..32].copy_from_slice(&tally.to_le_bytes());
    api::return_value(ReturnFlags::empty(), &output);
}

/// executes upgrade if 2/3 majority reached and timelock passed
fn execute_upgrade() {
    let mut pending = [0u8; 20];
    api::get_storage(&PENDING_IMPL_KEY, &mut pending);

    if pending == [0u8; 20] {
        api::return_value(ReturnFlags::REVERT, b"no pending upgrade");
        return;
    }

    let mut yes_bytes = [0u8; 2];
    api::get_storage(&UPGRADE_YES_WEIGHT_KEY, &mut yes_bytes);
    let yes_weight = u16::from_le_bytes(yes_bytes);

    let mut no_bytes = [0u8; 2];
    api::get_storage(&UPGRADE_NO_WEIGHT_KEY, &mut no_bytes);
    let no_weight = u16::from_le_bytes(no_bytes);

    let total = yes_weight + no_weight;
    if total == 0 || (yes_weight * 3) < (total * 2) {
        api::return_value(ReturnFlags::REVERT, b"need 2/3 majority");
        return;
    }

    let mut templar = [0u8; 20];
    api::get_storage(&TEMPLAR_KEY, &mut templar);

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    // templar can bypass timelock
    if templar != [0u8; 20] && caller == templar {
        api::set_storage(&IMPLEMENTATION_KEY, &pending);
        api::set_storage(&PENDING_IMPL_KEY, &[0u8; 20]);
        api::set_storage(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
        api::set_storage(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);
        api::return_value(ReturnFlags::empty(), &[1u8]);
        return;
    }

    let mut proposal_time = [0u8; 8];
    api::get_storage(&UPGRADE_PROPOSAL_KEY, &mut proposal_time);
    let proposal_timestamp = u64::from_le_bytes(proposal_time);

    let mut current_time = [0u8; 32];
    api::now(&mut current_time);
    let mut time_bytes = [0u8; 8];
    time_bytes.copy_from_slice(&current_time[..8]);
    let current_timestamp = u64::from_le_bytes(time_bytes);

    if current_timestamp < proposal_timestamp + 172800 {
        api::return_value(ReturnFlags::REVERT, b"48h delay required");
        return;
    }

    api::set_storage(&IMPLEMENTATION_KEY, &pending);
    api::set_storage(&PENDING_IMPL_KEY, &[0u8; 20]);
    api::set_storage(&UPGRADE_YES_WEIGHT_KEY, &[0u8; 2]);
    api::set_storage(&UPGRADE_NO_WEIGHT_KEY, &[0u8; 2]);

    api::return_value(ReturnFlags::empty(), &[1u8]);
}

/// removes templar privileges permanently
fn remove_templar() {
    let mut templar = [0u8; 20];
    api::get_storage(&TEMPLAR_KEY, &mut templar);

    let mut caller = [0u8; 20];
    api::caller(&mut caller);

    if caller != templar {
        api::return_value(ReturnFlags::REVERT, b"not templar");
        return;
    }

    api::set_storage(&TEMPLAR_KEY, &[0u8; 20]);
    api::return_value(ReturnFlags::empty(), &[]);
}

/// returns current implementation address
fn get_implementation() {
    let mut implementation = [0u8; 20];
    api::get_storage(&IMPLEMENTATION_KEY, &mut implementation);

    let mut output = [0u8; 32];
    output[12..32].copy_from_slice(&implementation);
    api::return_value(ReturnFlags::empty(), &output);
}

/// returns pending upgrade implementation address
fn get_pending_upgrade() {
    let mut pending = [0u8; 20];
    api::get_storage(&PENDING_IMPL_KEY, &mut pending);

    let mut output = [0u8; 32];
    output[12..32].copy_from_slice(&pending);
    api::return_value(ReturnFlags::empty(), &output);
}

/// queries implementation for voter weight based on level
fn get_voter_weight(voter: &[u8; 20]) -> u8 {
    let mut level = [0u8; 1];
    api::get_storage(&pylon_level_key(voter), &mut level);
    
    match level[0] {
        5 => 1,
        6 => 2,
        7 => 3,
        _ => 0,
    }
}

/// delegates all other calls to implementation contract
fn delegate_to_implementation() {
    let mut implementation = [0u8; 20];
    api::get_storage(&IMPLEMENTATION_KEY, &mut implementation);

    let data_len = api::call_data_size() as usize;
    const MAX_DATA: usize = 8192;

    if data_len > MAX_DATA {
        api::return_value(ReturnFlags::REVERT, b"data too large");
        return;
    }

    let mut data_buf = [0u8; MAX_DATA];
    let data = &mut data_buf[..data_len];
    api::call_data_copy(data, 0);

    let mut output_buf = [0u8; MAX_DATA];
    let mut output = &mut output_buf[..];

    match api::delegate_call(
        CallFlags::empty(),
        &implementation,
        api::gas_limit() * 9 / 10,
        0,
        &[0u8; 32],
        data,
        Some(&mut output)
    ) {
        Ok(()) => api::return_value(ReturnFlags::empty(), output),
        Err(_) => api::return_value(ReturnFlags::REVERT, &[]),
    }
}

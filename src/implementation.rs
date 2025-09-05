#![no_main]
#![no_std]

use uapi::{HostFn, HostFnImpl as api, ReturnFlags};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
   unsafe {
       core::arch::asm!("unimp");
       core::hint::unreachable_unchecked();
   }
}

// Storage key prefixes
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
const REPORT_INTERVAL: u64 = 300; // 5 minutes
const DEGRADATION_THRESHOLD: u8 = 95; // 95% uptime required
const MIN_PROBES_FOR_CONSENSUS: u8 = 3;

// Storage key generators
/// generates storage key for pylon's membership level (5-7)
fn pylon_level_key(pylon: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PYLON_LEVEL_PREFIX;
   key[1..21].copy_from_slice(pylon);
   key
}

/// generates storage key for network metadata by id
fn network_key(id: u32) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = NETWORK_PREFIX;
   key[1..5].copy_from_slice(&id.to_le_bytes());
   key
}

/// generates storage key to check if pylon is on specific network
fn pylon_key(network_id: u32, pylon: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PYLON_PREFIX;
   key[1..5].copy_from_slice(&network_id.to_le_bytes());
   key[5..25].copy_from_slice(pylon);
   key
}

/// generates storage key for dns settings per network and organization
fn dns_key(network_id: u32, org_id: u8) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = DNS_PREFIX;
   key[1..5].copy_from_slice(&network_id.to_le_bytes());
   key[5] = org_id;
   key
}

/// generates storage key for organization metadata
fn org_key(org_id: u8) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = ORG_PREFIX;
   key[1] = org_id;
   key
}

/// generates storage key for pylon's organization affiliation
fn pylon_org_key(pylon: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PYLON_ORG_PREFIX;
   key[1..21].copy_from_slice(pylon);
   key
}

/// generates storage key for dns controller address per organization
fn dns_controller_key(org_id: u8) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = DNS_CONTROLLER_PREFIX;
   key[1] = org_id;
   key
}

/// generates storage key for proposal metadata
fn proposal_key(id: u32) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PROPOSAL_PREFIX;
   key[1..5].copy_from_slice(&id.to_le_bytes());
   key
}

/// generates storage key for proposal execution data
fn proposal_data_key(id: u32) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PROPOSAL_DATA_PREFIX;
   key[1..5].copy_from_slice(&id.to_le_bytes());
   key
}

/// generates storage key for individual vote record
fn vote_key(proposal_id: u32, voter: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = VOTE_PREFIX;
   key[1..5].copy_from_slice(&proposal_id.to_le_bytes());
   key[5..25].copy_from_slice(voter);
   key
}

/// generates storage key for vote weight tally
fn vote_weight_key(proposal_id: u32, support: bool) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = VOTE_WEIGHT_PREFIX;
   key[1..5].copy_from_slice(&proposal_id.to_le_bytes());
   key[5] = support as u8;
   key
}

/// generates storage key for probe data in 5-minute windows
fn probe_window_key(pylon: &[u8; 20], window: u32) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PROBE_WINDOW_PREFIX;
   key[1..21].copy_from_slice(pylon);
   key[21..25].copy_from_slice(&window.to_le_bytes());
   key
}

/// generates storage key to track if probe already reported in window
fn probe_report_key(pylon: &[u8; 20], window: u32, probe: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PROBE_REPORT_PREFIX;
   key[1..21].copy_from_slice(pylon);
   key[21..25].copy_from_slice(&window.to_le_bytes());
   key[25] = probe[0];
   key[26] = probe[1];
   key
}

/// generates storage key for pylon operational status
fn pylon_status_key(pylon: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PYLON_STATUS_PREFIX;
   key[1..21].copy_from_slice(pylon);
   key
}

/// generates storage key for probe whitelist status
fn probe_whitelist_key(probe: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PROBE_WHITELIST_PREFIX;
   key[1..21].copy_from_slice(probe);
   key
}

/// generates storage key for current pylon metrics
fn pylon_metrics_key(pylon: &[u8; 20]) -> [u8; 32] {
   let mut key = [0u8; 32];
   key[0] = PYLON_METRICS_PREFIX;
   key[1..21].copy_from_slice(pylon);
   key
}

/// initializes contract with two organizations and zeroed counters
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
   api::set_storage(&org_key(1), b"IBP");
   api::set_storage(&org_key(2), b"Dotters");
   api::set_storage(&NETWORK_COUNT_KEY, &0u32.to_le_bytes());
   api::set_storage(&PROPOSAL_COUNT_KEY, &0u32.to_le_bytes());
}

/// routes incoming calls to appropriate functions based on selector
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
   let mut selector = [0u8; 4];
   api::call_data_copy(&mut selector, 0);
   
   match u32::from_be_bytes(selector) {
       // network management
       0xd09de08a => create_network(),
       0xec7dbaa5 => set_network_dns(),
       0x42c9a3f3 => add_pylon(),
       0xb2d1b31f => remove_pylon(),
       
       // pylon management  
       0xb9b0f66f => set_pylon_org(),
       0xfcdae25a => set_pylon_level(),
       0x1f9840a8 => execute_set_pylon_level(),
       0xae169a50 => execute_set_pylon_org(),
       
       // dns controller management
       0x73cf575a => set_dns_controller(),
       0xa8c62e76 => get_dns_controller(),
       0xb2bdda30 => execute_set_dns_controller(),
       
       // probe management
       0x3af32abf => whitelist_probe(),
       0xc19d93fb => revoke_probe(),
       0x9a8a0592 => execute_whitelist_probe(),
       0xd892cd12 => execute_revoke_probe(),
       
       // governance
       0xda35a26f => propose(),
       0x15373e3d => vote(),
       0xece40cc1 => execute_proposal(),
       
       // query functions
       0xc5958af9 => get_network_info(),
       0x957888b7 => get_network_count(),
       0x013cf08b => get_proposal(),
       0x609ff1bd => get_pylon_level(),
       0xa776d498 => get_pylon_status(),
       0x7a9e5e4b => get_pylon_metrics(),
       0x2e46b05d => is_probe_whitelisted(),
       
       // monitoring
       0x8f32d59b => report_probe_data(),
       0x4e487b71 => finalize_window(),
       
       _ => api::return_value(ReturnFlags::REVERT, &[]),
   }
}

/// creates new network with caller as first pylon, requires level 5+
fn create_network() {
   let mut caller = [0u8; 20];
   api::caller(&mut caller);
   
   let mut level = [0u8; 1];
   api::get_storage(&pylon_level_key(&caller), &mut level);
   
   if level[0] < 5 {
       api::return_value(ReturnFlags::REVERT, b"need level 5+");
       return;
   }
   
   let mut count_bytes = [0u8; 4];
   api::get_storage(&NETWORK_COUNT_KEY, &mut count_bytes);
   let mut count = u32::from_le_bytes(count_bytes);
   
   count += 1;
   let network_id = count;
   
   api::set_storage(&NETWORK_COUNT_KEY, &count.to_le_bytes());
   api::set_storage(&network_key(network_id), &level);
   api::set_storage(&pylon_key(network_id, &caller), &[1u8]);
   
   let mut output = [0u8; 32];
   output[28..32].copy_from_slice(&network_id.to_be_bytes());
   api::return_value(ReturnFlags::empty(), &output);
}

/// enables or disables dns for organization on network
fn set_network_dns() {
   let mut input = [0u8; 68];
   api::call_data_copy(&mut input, 4);
   
   let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
   let org_id = input[63];
   let enabled = input[95] != 0;
   
   if org_id != 1 && org_id != 2 {
       api::return_value(ReturnFlags::REVERT, b"invalid org");
       return;
   }
   
   let mut caller = [0u8; 20];
   api::caller(&mut caller);
   
   let mut controller = [0u8; 20];
   api::get_storage(&dns_controller_key(org_id), &mut controller);
   
   let mut is_pylon = [0u8; 1];
   api::get_storage(&pylon_key(network_id, &caller), &mut is_pylon);
   
   let mut level = [0u8; 1];
   api::get_storage(&pylon_level_key(&caller), &mut level);
   
   if caller != controller && (is_pylon[0] == 0 || level[0] < 5) {
       api::return_value(ReturnFlags::REVERT, b"not authorized");
       return;
   }
   
   api::set_storage(&dns_key(network_id, org_id), &[enabled as u8]);
   api::return_value(ReturnFlags::empty(), &[]);
}

/// adds new pylon to network, requires existing level 5+ pylon
fn add_pylon() {
   let mut input = [0u8; 64];
   api::call_data_copy(&mut input, 4);
   
   let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
   let mut new_pylon = [0u8; 20];
   new_pylon.copy_from_slice(&input[44..64]);
   
   let mut caller = [0u8; 20];
   api::caller(&mut caller);
   
   let mut is_pylon = [0u8; 1];
   api::get_storage(&pylon_key(network_id, &caller), &mut is_pylon);
   
   let mut level = [0u8; 1];
   api::get_storage(&pylon_level_key(&caller), &mut level);
   
   if is_pylon[0] == 0 || level[0] < 5 {
       api::return_value(ReturnFlags::REVERT, b"not authorized");
       return;
   }
   
   api::set_storage(&pylon_key(network_id, &new_pylon), &[1u8]);
   api::set_storage(&pylon_status_key(&new_pylon), &[0u8]); // active by default
   api::return_value(ReturnFlags::empty(), &[]);
}

/// removes pylon from network, requires governance
fn remove_pylon() {
   api::return_value(ReturnFlags::REVERT, b"use governance");
}

/// sets pylon organization affiliation, creates proposal
fn set_pylon_org() {
   let mut input = [0u8; 36];
   api::call_data_copy(&mut input, 4);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&input[12..32]);
   let org_id = input[63];
   
   if org_id != 1 && org_id != 2 {
       api::return_value(ReturnFlags::REVERT, b"invalid org");
       return;
   }
   
   create_proposal(2, &pylon, org_id);
}

/// sets pylon membership level, creates proposal
fn set_pylon_level() {
   let mut input = [0u8; 36];
   api::call_data_copy(&mut input, 4);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&input[12..32]);
   let new_level = input[63];
   
   if new_level > 7 {
       api::return_value(ReturnFlags::REVERT, b"max level 7");
       return;
   }
   
   create_proposal(1, &pylon, new_level);
}

/// sets dns controller for organization, creates proposal
fn set_dns_controller() {
   let mut input = [0u8; 36];
   api::call_data_copy(&mut input, 4);
   
   let org_id = input[31];
   let mut controller = [0u8; 20];
   controller.copy_from_slice(&input[44..64]);
   
   if org_id != 1 && org_id != 2 {
       api::return_value(ReturnFlags::REVERT, b"invalid org");
       return;
   }
   
   create_proposal(3, &controller, org_id);
}

/// whitelists probe for monitoring, creates proposal
fn whitelist_probe() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let mut probe = [0u8; 20];
   probe.copy_from_slice(&input[12..32]);
   
   create_proposal(4, &probe, 1);
}

/// revokes probe whitelist, creates proposal
fn revoke_probe() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let mut probe = [0u8; 20];
   probe.copy_from_slice(&input[12..32]);
   
   create_proposal(5, &probe, 0);
}

/// creates governance proposal with type, target and value
fn create_proposal(proposal_type: u8, target: &[u8; 20], value: u8) {
   let mut caller = [0u8; 20];
   api::caller(&mut caller);
   
   let mut level = [0u8; 1];
   api::get_storage(&pylon_level_key(&caller), &mut level);
   
   if level[0] < 5 {
       api::return_value(ReturnFlags::REVERT, b"need level 5+");
       return;
   }
   
   let mut count_bytes = [0u8; 4];
   api::get_storage(&PROPOSAL_COUNT_KEY, &mut count_bytes);
   let mut count = u32::from_le_bytes(count_bytes);
   count += 1;
   
   let mut proposal_meta = [0u8; 32];
   proposal_meta[0] = proposal_type;
   proposal_meta[1..21].copy_from_slice(&caller);
   api::set_storage(&proposal_key(count), &proposal_meta);
   
   let mut proposal_data = [0u8; 32];
   proposal_data[0..20].copy_from_slice(target);
   proposal_data[20] = value;
   api::set_storage(&proposal_data_key(count), &proposal_data);
   
   api::set_storage(&PROPOSAL_COUNT_KEY, &count.to_le_bytes());
   
   let mut output = [0u8; 32];
   output[28..32].copy_from_slice(&count.to_be_bytes());
   api::return_value(ReturnFlags::empty(), &output);
}

/// creates proposal through specific setter functions
fn propose() {
   let mut input = [0u8; 36];
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

/// casts weighted vote on proposal
fn vote() {
   let mut input = [0u8; 36];
   api::call_data_copy(&mut input, 4);
   
   let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
   let support = input[63] != 0;
   
   let mut voter = [0u8; 20];
   api::caller(&mut voter);
   
   let mut level = [0u8; 1];
   api::get_storage(&pylon_level_key(&voter), &mut level);
   
   if level[0] < 5 {
       api::return_value(ReturnFlags::REVERT, b"need level 5+");
       return;
   }
   
   let mut existing_vote = [0u8; 1];
   api::get_storage(&vote_key(proposal_id, &voter), &mut existing_vote);
   
   if existing_vote[0] != 0 {
       api::return_value(ReturnFlags::REVERT, b"already voted");
       return;
   }
   
   let weight = calculate_vote_weight(level[0]);
   
   api::set_storage(&vote_key(proposal_id, &voter), &[support as u8 + 1]);
   
   let mut tally_bytes = [0u8; 2];
   api::get_storage(&vote_weight_key(proposal_id, support), &mut tally_bytes);
   let mut tally = u16::from_le_bytes(tally_bytes);
   tally += weight as u16;
   api::set_storage(&vote_weight_key(proposal_id, support), &tally.to_le_bytes());
   
   let mut output = [0u8; 32];
   output[30..32].copy_from_slice(&tally.to_le_bytes());
   api::return_value(ReturnFlags::empty(), &output);
}

/// executes proposal if 2/3 majority reached
fn execute_proposal() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
   
   let mut yes_bytes = [0u8; 2];
   api::get_storage(&vote_weight_key(proposal_id, true), &mut yes_bytes);
   let yes_weight = u16::from_le_bytes(yes_bytes);
   
   let mut no_bytes = [0u8; 2];
   api::get_storage(&vote_weight_key(proposal_id, false), &mut no_bytes);
   let no_weight = u16::from_le_bytes(no_bytes);
   
   let total = yes_weight + no_weight;
   if total == 0 || (yes_weight * 3) < (total * 2) {
       api::return_value(ReturnFlags::REVERT, b"need 2/3 majority");
       return;
   }
   
   let mut proposal_meta = [0u8; 32];
   api::get_storage(&proposal_key(proposal_id), &mut proposal_meta);
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

/// applies pylon level change from approved proposal
fn execute_set_pylon_level() {
   execute_proposal();
}

fn execute_set_pylon_level_internal(proposal_id: u32) {
   let mut proposal_data = [0u8; 32];
   api::get_storage(&proposal_data_key(proposal_id), &mut proposal_data);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&proposal_data[0..20]);
   let new_level = proposal_data[20];
   
   api::set_storage(&pylon_level_key(&pylon), &[new_level]);
   
   let mut output = [0u8; 32];
   output[31] = 1;
   api::return_value(ReturnFlags::empty(), &output);
}

/// applies pylon organization change from approved proposal
fn execute_set_pylon_org() {
   execute_proposal();
}

fn execute_set_pylon_org_internal(proposal_id: u32) {
   let mut proposal_data = [0u8; 32];
   api::get_storage(&proposal_data_key(proposal_id), &mut proposal_data);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&proposal_data[0..20]);
   let org_id = proposal_data[20];
   
   api::set_storage(&pylon_org_key(&pylon), &[org_id]);
   
   let mut output = [0u8; 32];
   output[31] = 1;
   api::return_value(ReturnFlags::empty(), &output);
}

/// applies dns controller change from approved proposal
fn execute_set_dns_controller() {
   execute_proposal();
}

fn execute_set_dns_controller_internal(proposal_id: u32) {
   let mut proposal_data = [0u8; 32];
   api::get_storage(&proposal_data_key(proposal_id), &mut proposal_data);
   
   let mut controller = [0u8; 20];
   controller.copy_from_slice(&proposal_data[0..20]);
   let org_id = proposal_data[20];
   
   api::set_storage(&dns_controller_key(org_id), &controller);
   
   let mut output = [0u8; 32];
   output[31] = 1;
   api::return_value(ReturnFlags::empty(), &output);
}

/// whitelists probe address from approved proposal
fn execute_whitelist_probe() {
   execute_proposal();
}

fn execute_whitelist_probe_internal(proposal_id: u32) {
   let mut proposal_data = [0u8; 32];
   api::get_storage(&proposal_data_key(proposal_id), &mut proposal_data);
   
   let mut probe = [0u8; 20];
   probe.copy_from_slice(&proposal_data[0..20]);
   
   api::set_storage(&probe_whitelist_key(&probe), &[1u8]);
   
   let mut output = [0u8; 32];
   output[31] = 1;
   api::return_value(ReturnFlags::empty(), &output);
}

/// revokes probe whitelist from approved proposal
fn execute_revoke_probe() {
   execute_proposal();
}

fn execute_revoke_probe_internal(proposal_id: u32) {
   let mut proposal_data = [0u8; 32];
   api::get_storage(&proposal_data_key(proposal_id), &mut proposal_data);
   
   let mut probe = [0u8; 20];
   probe.copy_from_slice(&proposal_data[0..20]);
   
   api::set_storage(&probe_whitelist_key(&probe), &[0u8]);
   
   let mut output = [0u8; 32];
   output[31] = 1;
   api::return_value(ReturnFlags::empty(), &output);
}

/// returns network configuration including level requirement and dns settings
fn get_network_info() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let network_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
   
   let mut level_req = [0u8; 1];
   api::get_storage(&network_key(network_id), &mut level_req);
   
   let mut ibp_dns = [0u8; 1];
   api::get_storage(&dns_key(network_id, 1), &mut ibp_dns);
   
   let mut dotters_dns = [0u8; 1];
   api::get_storage(&dns_key(network_id, 2), &mut dotters_dns);
   
   let mut output = [0u8; 32];
   output[29] = level_req[0];
   output[30] = ibp_dns[0];
   output[31] = dotters_dns[0];
   api::return_value(ReturnFlags::empty(), &output);
}

/// returns total number of networks created
fn get_network_count() {
   let mut count_bytes = [0u8; 4];
   api::get_storage(&NETWORK_COUNT_KEY, &mut count_bytes);
   let count = u32::from_le_bytes(count_bytes);
   
   let mut output = [0u8; 32];
   output[28..32].copy_from_slice(&count.to_be_bytes());
   api::return_value(ReturnFlags::empty(), &output);
}

/// returns dns controller address for specified organization
fn get_dns_controller() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let org_id = input[31];
   
   if org_id != 1 && org_id != 2 {
       api::return_value(ReturnFlags::REVERT, b"invalid org");
       return;
   }
   
   let mut controller = [0u8; 20];
   api::get_storage(&dns_controller_key(org_id), &mut controller);
   
   let mut output = [0u8; 32];
   output[12..32].copy_from_slice(&controller);
   api::return_value(ReturnFlags::empty(), &output);
}

/// returns proposal metadata including type and proposer
fn get_proposal() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let proposal_id = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
   
   let mut proposal_data = [0u8; 32];
   api::get_storage(&proposal_key(proposal_id), &mut proposal_data);
   
   api::return_value(ReturnFlags::empty(), &proposal_data);
}

/// returns membership level for specified pylon address
fn get_pylon_level() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&input[12..32]);
   
   let mut level = [0u8; 1];
   api::get_storage(&pylon_level_key(&pylon), &mut level);
   
   let mut output = [0u8; 32];
   output[31] = level[0];
   api::return_value(ReturnFlags::empty(), &output);
}

/// returns operational status of pylon (active/degraded/offline)
fn get_pylon_status() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&input[12..32]);
   
   let mut status = [0u8; 1];
   api::get_storage(&pylon_status_key(&pylon), &mut status);
   
   let mut output = [0u8; 32];
   output[31] = status[0];
   api::return_value(ReturnFlags::empty(), &output);
}

/// returns current metrics for pylon
fn get_pylon_metrics() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&input[12..32]);
   
   let mut metrics = [0u8; 16];
   api::get_storage(&pylon_metrics_key(&pylon), &mut metrics);
   
   let mut output = [0u8; 32];
   output[16..32].copy_from_slice(&metrics);
   api::return_value(ReturnFlags::empty(), &output);
}

/// checks if probe address is whitelisted
fn is_probe_whitelisted() {
   let mut input = [0u8; 32];
   api::call_data_copy(&mut input, 4);
   
   let mut probe = [0u8; 20];
   probe.copy_from_slice(&input[12..32]);
   
   let mut whitelisted = [0u8; 1];
   api::get_storage(&probe_whitelist_key(&probe), &mut whitelisted);
   
   let mut output = [0u8; 32];
   output[31] = whitelisted[0];
   api::return_value(ReturnFlags::empty(), &output);
}

/// accepts probe data for pylon monitoring, only from whitelisted probes
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
   
   // check if probe is whitelisted
   let mut whitelisted = [0u8; 1];
   api::get_storage(&probe_whitelist_key(&caller), &mut whitelisted);
   
   if whitelisted[0] == 0 {
       api::return_value(ReturnFlags::REVERT, b"probe not whitelisted");
       return;
   }
   
   // verify pylon exists
   let mut pylon_level = [0u8; 1];
   api::get_storage(&pylon_level_key(&pylon), &mut pylon_level);
   
   if pylon_level[0] == 0 {
       api::return_value(ReturnFlags::REVERT, b"invalid pylon");
       return;
   }
   
   // get current window
   let mut current_time = [0u8; 8];
   api::block_timestamp(&mut current_time);
   let current_timestamp = u64::from_le_bytes(current_time);
   let window = (current_timestamp / REPORT_INTERVAL) as u32;
   
   // check if already reported in this window
   let mut reported = [0u8; 1];
   api::get_storage(&probe_report_key(&pylon, window, &caller), &mut reported);
   
   if reported[0] != 0 {
       api::return_value(ReturnFlags::REVERT, b"already reported");
       return;
   }
   
   // mark as reported
   api::set_storage(&probe_report_key(&pylon, window, &caller), &[1u8]);
   
   // update window data
   let mut window_data = [0u8; 12];
   api::get_storage(&probe_window_key(&pylon, window), &mut window_data);
   
   let mut report_count = window_data[0];
   let mut total_uptime = u16::from_le_bytes([window_data[1], window_data[2]]);
   let mut total_latency = u32::from_le_bytes([window_data[3], window_data[4], window_data[5], window_data[6]]);
   let mut regions_coverage = u32::from_le_bytes([window_data[7], window_data[8], window_data[9], window_data[10]]);
   
   report_count += 1;
   total_uptime += uptime as u16;
   total_latency += latency as u32;
   regions_coverage |= regions; // OR to combine region coverage
   
   window_data[0] = report_count;
   window_data[1..3].copy_from_slice(&total_uptime.to_le_bytes());
   window_data[3..7].copy_from_slice(&total_latency.to_le_bytes());
   window_data[7..11].copy_from_slice(&regions_coverage.to_le_bytes());
   
   api::set_storage(&probe_window_key(&pylon, window), &window_data);
   
   let mut output = [0u8; 32];
   output[28..32].copy_from_slice(&window.to_be_bytes());
   api::return_value(ReturnFlags::empty(), &output);
}

/// finalizes window and updates pylon status based on consensus
fn finalize_window() {
   let mut input = [0u8; 36];
   api::call_data_copy(&mut input, 4);
   
   let mut pylon = [0u8; 20];
   pylon.copy_from_slice(&input[12..32]);
   let window = u32::from_be_bytes([input[32], input[33], input[34], input[35]]);
   
   // get current window
   let mut current_time = [0u8; 8];
   api::block_timestamp(&mut current_time);
   let current_timestamp = u64::from_le_bytes(current_time);
   let current_window = (current_timestamp / REPORT_INTERVAL) as u32;
   
   // can only finalize completed windows
   if window >= current_window {
       api::return_value(ReturnFlags::REVERT, b"window not complete");
       return;
   }
   
   // get window data
   let mut window_data = [0u8; 12];
   api::get_storage(&probe_window_key(&pylon, window), &mut window_data);
   
   let report_count = window_data[0];
   
   if report_count < MIN_PROBES_FOR_CONSENSUS {
       // not enough probes, mark as unknown
       api::set_storage(&pylon_status_key(&pylon), &[2u8]); // 0=active, 1=degraded, 2=unknown
       api::return_value(ReturnFlags::empty(), &[2u8]);
       return;
   }
   
   let total_uptime = u16::from_le_bytes([window_data[1], window_data[2]]);
   let total_latency = u32::from_le_bytes([window_data[3], window_data[4], window_data[5], window_data[6]]);
   let regions = u32::from_le_bytes([window_data[7], window_data[8], window_data[9], window_data[10]]);
   
   let avg_uptime = (total_uptime / report_count as u16) as u8;
   let avg_latency = (total_latency / report_count as u32) as u16;
   
   // determine status based on metrics
   let status = if avg_uptime < DEGRADATION_THRESHOLD {
       1u8 // degraded
   } else {
       0u8 // active
   };
   
   // update pylon status
   api::set_storage(&pylon_status_key(&pylon), &[status]);
   
   // store current metrics
   let mut metrics = [0u8; 16];
   metrics[0] = avg_uptime;
   metrics[1..3].copy_from_slice(&avg_latency.to_le_bytes());
   metrics[3..7].copy_from_slice(&regions.to_le_bytes());
   metrics[7..11].copy_from_slice(&window.to_le_bytes());
   metrics[11] = report_count;
   
   api::set_storage(&pylon_metrics_key(&pylon), &metrics);
   
   // clear window data to free storage
   api::set_storage(&probe_window_key(&pylon, window), &[0u8; 12]);
   
   let mut output = [0u8; 32];
   output[31] = status;
   api::return_value(ReturnFlags::empty(), &output);
}

/// calculates voting weight based on membership level
fn calculate_vote_weight(level: u8) -> u8 {
   match level {
       5 => 1,
       6 => 2,
       7 => 3,
       _ => 0,
   }
}

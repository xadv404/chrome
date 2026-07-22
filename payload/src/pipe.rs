//! Named pipe IPC client for injector communication.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_NONE, OPEN_EXISTING,
};

pub struct PipeClient {
    handle: HANDLE,
}

impl PipeClient {
    pub unsafe fn connect(pipe_name: *const u16) -> Result<Self, ()> {
        if pipe_name.is_null() {
            return Err(());
        }
        let handle = CreateFileW(
            PCWSTR(pipe_name),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
        .map_err(|_| ())?;
        Ok(Self { handle })
    }

    pub fn send_line(&self, line: &str) -> Result<(), ()> {
        let mut msg = line.as_bytes().to_vec();
        msg.push(b'\n');
        unsafe {
            let mut written = 0u32;
            WriteFile(
                self.handle,
                Some(&msg),
                Some(&mut written),
                None,
            )
            .map_err(|_| ())?;
        }
        Ok(())
    }

    pub fn send_status(&self, msg: &str) -> Result<(), ()> {
        let json = format!(r#"{{"type":"status","msg":{}}}"#, json_string(msg));
        self.send_line(&json)
    }

    pub fn send_result(&self, master_key_hex: &str, browser: &str) -> Result<(), ()> {
        let json = format!(
            r#"{{"type":"result","browser":{},"master_key_hex":{}}}"#,
            json_string(browser),
            json_string(master_key_hex)
        );
        self.send_line(&json)
    }

    pub fn send_error(&self, msg: &str) -> Result<(), ()> {
        let json = format!(r#"{{"type":"error","msg":{}}}"#, json_string(msg));
        self.send_line(&json)
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn json_string(s: &str) -> String {
    let escaped: String = s
        .chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<String>(),
            '"' => "\\\"".chars().collect::<String>(),
            '\n' => "\\n".chars().collect::<String>(),
            '\r' => "\\r".chars().collect::<String>(),
            _ => c.to_string(),
        })
        .collect();
    format!("\"{escaped}\"")
}

pub unsafe fn connect_pipe_name(pipe_name: *const u16) -> Result<PipeClient, ()> {
    PipeClient::connect(pipe_name)
}

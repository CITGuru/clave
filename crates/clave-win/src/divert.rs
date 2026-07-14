//! WinDivert-backed network split-tunnel enforcement (doc 08 §2).
//!
//! At the WinDivert **socket layer** every outbound connect carries the initiating process id
//! and remote address. That lets the daemon drop a connection from a work-zone process to a
//! policy-blocked destination *before it is established* — a real kernel-mediated control, unlike
//! the loopback data-plane stub. `WinDivert.dll` is loaded at runtime, so this crate builds
//! without the SDK and the daemon degrades cleanly (staying on the loopback path) when the driver
//! is absent or it is not running elevated.

#[cfg(any(windows, test))]
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetVerdict {
    Allow,
    Block,
}

/// Size of `WINDIVERT_ADDRESS` (v2.2): `INT64` timestamp + one packed `UINT32` of bitfields +
/// `UINT32` reserved + a 64-byte union. Only the WinDivert driver and its cross-platform parse
/// tests read this layer, so it is gated to avoid dead-code noise on a plain non-Windows build.
#[cfg(any(windows, test))]
pub const WINDIVERT_ADDRESS_LEN: usize = 80;

#[cfg(any(windows, test))]
const EVENT_SOCKET_CONNECT: u8 = 4;

/// A decoded outbound-connect event from a `WINDIVERT_ADDRESS` at the socket layer.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketEvent {
    pub event: u8,
    pub outbound: bool,
    pub ipv6: bool,
    pub pid: u32,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: u16,
}

#[cfg(any(windows, test))]
impl SocketEvent {
    pub fn is_outbound_connect(&self) -> bool {
        self.event == EVENT_SOCKET_CONNECT && self.outbound
    }
}

/// Decodes the fields we act on from the raw `WINDIVERT_ADDRESS` bytes. Offsets follow
/// `windivert.h` (`WINDIVERT_DATA_SOCKET` inside the address union) and the byte ordering the
/// official `socketdump` sample uses: `RemoteAddr[0]` is a host-order `UINT32` and ports are
/// network-order. Kept pure so the FFI struct layout is regression-tested without the driver.
#[cfg(any(windows, test))]
pub fn parse_socket_address(buf: &[u8]) -> Option<SocketEvent> {
    if buf.len() < WINDIVERT_ADDRESS_LEN {
        return None;
    }
    // MSVC packs the bitfield word from the least-significant bit: Layer[0..8], Event[8..16],
    // Sniffed[16], Outbound[17], Loopback[18], Impostor[19], IPv6[20], ...
    let bits = u32::from_ne_bytes(buf[8..12].try_into().ok()?);
    let event = ((bits >> 8) & 0xFF) as u8;
    let outbound = (bits >> 17) & 1 == 1;
    let ipv6 = (bits >> 20) & 1 == 1;

    let data = &buf[16..WINDIVERT_ADDRESS_LEN];
    let pid = u32::from_ne_bytes(data[16..20].try_into().ok()?);
    let remote_port = u16::from_be_bytes(data[54..56].try_into().ok()?);
    let remote_ip = if ipv6 {
        // IPv6 remote-address decoding (four host-order UINT32s in reverse) is not needed for the
        // current IPv4 policy set; treat v6 connects as unclassified (allowed) rather than guess.
        None
    } else {
        let v = u32::from_ne_bytes(data[36..40].try_into().ok()?);
        Some(IpAddr::V4(Ipv4Addr::from(v)))
    };

    Some(SocketEvent {
        event,
        outbound,
        ipv6,
        pid,
        remote_ip,
        remote_port,
    })
}

#[cfg(windows)]
pub use driver::run_split_tunnel;

#[cfg(windows)]
#[allow(unsafe_code)]
mod driver {
    use super::{parse_socket_address, NetVerdict, WINDIVERT_ADDRESS_LEN};
    use clave_core::ZoneRegistry;
    use clave_platform::Zone;
    use std::net::IpAddr;
    use std::sync::Arc;
    use windows::core::{s, w, PCSTR};
    use windows::Win32::Foundation::{BOOL, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    const LAYER_SOCKET: i32 = 3;

    type FnOpen = unsafe extern "system" fn(PCSTR, i32, i16, u64) -> HANDLE;
    type FnRecv = unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *mut u8) -> BOOL;
    type FnSend = unsafe extern "system" fn(HANDLE, *const u8, u32, *mut u32, *const u8) -> BOOL;

    struct WinDivert {
        open: FnOpen,
        recv: FnRecv,
        send: FnSend,
    }

    impl WinDivert {
        fn load() -> std::io::Result<Self> {
            unsafe {
                let module: HMODULE = LoadLibraryW(w!("WinDivert.dll")).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("WinDivert.dll not found next to the daemon: {e}"),
                    )
                })?;
                type FarProc = unsafe extern "system" fn() -> isize;
                let proc = |name: PCSTR| GetProcAddress(module, name);
                let (Some(open), Some(recv), Some(send)) = (
                    proc(s!("WinDivertOpen")),
                    proc(s!("WinDivertRecv")),
                    proc(s!("WinDivertSend")),
                ) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "WinDivert.dll is missing expected exports",
                    ));
                };
                Ok(Self {
                    open: std::mem::transmute::<FarProc, FnOpen>(open),
                    recv: std::mem::transmute::<FarProc, FnRecv>(recv),
                    send: std::mem::transmute::<FarProc, FnSend>(send),
                })
            }
        }
    }

    /// Opens a socket-layer WinDivert handle and enforces `decide` on every outbound connect:
    /// a `Block` verdict drops the event (the connection never establishes); everything else is
    /// re-injected untouched. Blocks forever on success; returns `Err` when the driver can't be
    /// opened (missing DLL, or not elevated) so the caller can stay on the loopback path.
    pub fn run_split_tunnel<F>(zones: Arc<ZoneRegistry>, mut decide: F) -> std::io::Result<()>
    where
        F: FnMut(Zone, IpAddr, u16) -> NetVerdict,
    {
        let api = WinDivert::load()?;

        // Non-sniff handle: to *allow* a socket event we must re-inject it, so a dropped event is
        // a blocked operation. A tight, default-allow loop keeps the machine's networking intact.
        let handle = unsafe { (api.open)(s!("outbound and (tcp or udp)"), LAYER_SOCKET, 0, 0) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "WinDivertOpen failed — run the daemon elevated (Administrator)",
            ));
        }

        let mut addr = [0u8; WINDIVERT_ADDRESS_LEN];
        loop {
            let mut recv_len = 0u32;
            let ok = unsafe {
                (api.recv)(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    &mut recv_len,
                    addr.as_mut_ptr(),
                )
            };
            if !ok.as_bool() {
                continue;
            }

            let mut allow = true;
            if let Some(ev) = parse_socket_address(&addr) {
                if ev.is_outbound_connect() {
                    if let Some(ip) = ev.remote_ip {
                        let zone = if zones.supervised_pids().contains(&ev.pid) {
                            Zone::Work
                        } else {
                            Zone::Personal
                        };
                        if decide(zone, ip, ev.remote_port) == NetVerdict::Block {
                            allow = false;
                            eprintln!(
                                "clave-win: blocked work-zone connect to {ip}:{} (pid {})",
                                ev.remote_port, ev.pid
                            );
                        }
                    }
                }
            }

            if allow {
                unsafe {
                    let _ = (api.send)(handle, std::ptr::null(), 0, std::ptr::null_mut(), addr.as_ptr());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic socket-layer `WINDIVERT_ADDRESS` for an outbound IPv4 connect.
    fn connect_addr(pid: u32, ip: Ipv4Addr, port: u16) -> [u8; WINDIVERT_ADDRESS_LEN] {
        let mut buf = [0u8; WINDIVERT_ADDRESS_LEN];
        // Event = CONNECT (bits 8..16), Outbound = bit 17.
        let bits: u32 = ((EVENT_SOCKET_CONNECT as u32) << 8) | (1 << 17);
        buf[8..12].copy_from_slice(&bits.to_ne_bytes());
        let data = &mut buf[16..];
        data[16..20].copy_from_slice(&pid.to_ne_bytes());
        data[36..40].copy_from_slice(&u32::from(ip).to_ne_bytes());
        data[54..56].copy_from_slice(&port.to_be_bytes());
        buf
    }

    #[test]
    fn decodes_pid_ip_and_port_from_a_connect_event() {
        let buf = connect_addr(4321, Ipv4Addr::new(192, 0, 2, 1), 443);
        let ev = parse_socket_address(&buf).expect("parse");
        assert!(ev.is_outbound_connect());
        assert_eq!(ev.pid, 4321);
        assert_eq!(ev.remote_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert_eq!(ev.remote_port, 443);
    }

    #[test]
    fn a_short_buffer_is_rejected_rather_than_misread() {
        assert!(parse_socket_address(&[0u8; 10]).is_none());
    }
}

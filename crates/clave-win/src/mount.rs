//! The Clave Disk on Windows: a WinFsp filesystem whose file bytes live only as XTS-AES-256
//! ciphertext (doc 05 §3).
//!
//! Every regular file's contents are held sector-aligned and encrypted with the volume's DEK
//! through `clave-volume`'s [`XtsCipher`] — the same cipher the sealed block device uses — and are
//! decrypted transiently on read. Plaintext never persists in the node table, so a memory image of
//! the mount yields only ciphertext. `WinDivert.dll`-style delay-loading applies here too: the
//! WinFsp runtime is loaded at start, so the crate builds without the SDK and the daemon degrades
//! to `unavailable` when WinFsp is not installed.
//!
//! Custody is software-only on this lab build (no Secure Enclave / TPM), so the honest posture is
//! `development-only`: the encryption is real, but the key is not hardware-rooted.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use clave_volume::{Dek, XtsCipher, SECTOR_SIZE};

use winfsp::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo,
    WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::{FspError, U16CStr};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003Au32 as i32;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033u32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103u32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: i32 = 0xC000_0101u32 as i32;
const STATUS_END_OF_FILE: i32 = 0xC000_0011u32 as i32;
const STATUS_DISK_FULL: i32 = 0xC000_007Fu32 as i32;

fn nt(code: i32) -> FspError {
    FspError::NTSTATUS(code)
}

/// Windows `FILETIME`: 100ns ticks since 1601-01-01.
fn filetime_now() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs() * 10_000_000 + (now.subsec_nanos() as u64) / 100 + 116_444_736_000_000_000
}

fn round_up(n: usize, unit: usize) -> usize {
    n.div_ceil(unit) * unit
}

/// Canonical (case-folded, no trailing separator) key for a WinFsp path. The root is `\`.
fn canon(path: &str) -> String {
    let mut p = path.to_string();
    if p.is_empty() {
        p.push('\\');
    }
    while p.len() > 1 && p.ends_with('\\') {
        p.pop();
    }
    p.to_uppercase()
}

/// Canonical key of a path's parent directory, or `None` for the root.
fn parent_canon(canon_path: &str) -> Option<String> {
    if canon_path == "\\" {
        return None;
    }
    match canon_path.rfind('\\') {
        Some(0) => Some("\\".to_string()),
        Some(i) => Some(canon_path[..i].to_string()),
        None => None,
    }
}

/// The final `\`-separated component of a path, with original case preserved.
fn basename(path: &str) -> &str {
    match path.rfind('\\') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// One filesystem node. For files, `data` holds ciphertext padded to a whole number of sectors;
/// `size` is the logical length. Directories carry no data.
struct Node {
    /// Full path with original case, e.g. `\Reports\q3.txt`.
    name: String,
    is_dir: bool,
    attributes: u32,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    index_number: u64,
    data: Vec<u8>,
    size: u64,
}

impl Node {
    fn file_info(&self) -> FileInfo {
        FileInfo {
            file_attributes: self.attributes,
            reparse_tag: 0,
            allocation_size: round_up(self.size as usize, SECTOR_SIZE) as u64,
            file_size: self.size,
            creation_time: self.creation_time,
            last_access_time: self.last_access_time,
            last_write_time: self.last_write_time,
            change_time: self.change_time,
            index_number: self.index_number,
            hard_links: 0,
            ea_size: 0,
        }
    }
}

struct State {
    nodes: HashMap<u64, Node>,
    by_path: HashMap<String, u64>,
    next_id: u64,
    next_index: u64,
    label: Vec<u16>,
}

impl State {
    fn id_of(&self, canon_path: &str) -> Option<u64> {
        self.by_path.get(canon_path).copied()
    }

    fn get(&self, id: u64) -> &Node {
        self.nodes.get(&id).expect("live clave-disk handle")
    }

    fn get_mut(&mut self, id: u64) -> &mut Node {
        self.nodes.get_mut(&id).expect("live clave-disk handle")
    }

    /// True if `dir_canon` has at least one direct child (used to keep directory delete safe).
    fn has_children(&self, dir_canon: &str) -> bool {
        self.nodes.values().any(|n| {
            let c = canon(&n.name);
            c != dir_canon && parent_canon(&c).as_deref() == Some(dir_canon)
        })
    }
}

/// The in-memory encrypting filesystem handed to WinFsp.
pub struct ClaveDiskFs {
    state: Mutex<State>,
    cipher: XtsCipher,
    capacity: u64,
    max_file_size: u64,
}

impl ClaveDiskFs {
    fn new(dek: &Dek, capacity: u64) -> Self {
        let now = filetime_now();
        let mut nodes = HashMap::new();
        let mut by_path = HashMap::new();
        nodes.insert(
            1,
            Node {
                name: "\\".to_string(),
                is_dir: true,
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
                index_number: 1,
                data: Vec::new(),
                size: 0,
            },
        );
        by_path.insert("\\".to_string(), 1);

        Self {
            state: Mutex::new(State {
                nodes,
                by_path,
                next_id: 2,
                next_index: 2,
                label: "ClaveDisk".encode_utf16().collect(),
            }),
            cipher: XtsCipher::new(dek),
            capacity,
            max_file_size: capacity,
        }
    }

    /// Decrypts a file node's ciphertext into plaintext of exactly `size` bytes.
    fn decrypt(&self, node: &Node) -> Vec<u8> {
        let mut buf = node.data.clone();
        if !buf.is_empty() {
            self.cipher.decrypt(&mut buf, 0);
        }
        buf.truncate(node.size as usize);
        buf
    }

    /// Encrypts `plain` back into a node, padding to a whole number of sectors so XTS always sees
    /// sector-sized input. `plain.len()` becomes the new logical size.
    fn store(&self, node: &mut Node, plain: Vec<u8>) {
        let size = plain.len() as u64;
        let mut ct = plain;
        let alloc = round_up(ct.len(), SECTOR_SIZE);
        ct.resize(alloc, 0);
        if !ct.is_empty() {
            self.cipher.encrypt(&mut ct, 0);
        }
        node.data = ct;
        node.size = size;
        let now = filetime_now();
        node.last_write_time = now;
        node.change_time = now;
    }
}

impl FileSystemContext for ClaveDiskFs {
    type FileContext = u64;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let state = self.state.lock().unwrap();
        let id = state
            .id_of(&canon(&file_name.to_string_lossy()))
            .ok_or_else(|| nt(STATUS_OBJECT_NAME_NOT_FOUND))?;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: state.get(id).attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let state = self.state.lock().unwrap();
        let id = state
            .id_of(&canon(&file_name.to_string_lossy()))
            .ok_or_else(|| nt(STATUS_OBJECT_NAME_NOT_FOUND))?;
        *file_info.as_mut() = state.get(id).file_info();
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let original = file_name.to_string_lossy();
        let key = canon(&original);
        let mut state = self.state.lock().unwrap();

        if state.id_of(&key).is_some() {
            return Err(nt(STATUS_OBJECT_NAME_COLLISION));
        }
        let parent = parent_canon(&key).ok_or_else(|| nt(STATUS_OBJECT_NAME_INVALID))?;
        let parent_id = state
            .id_of(&parent)
            .ok_or_else(|| nt(STATUS_OBJECT_PATH_NOT_FOUND))?;
        if !state.get(parent_id).is_dir {
            return Err(nt(STATUS_NOT_A_DIRECTORY));
        }

        let is_dir = (create_options & FILE_DIRECTORY_FILE) != 0;
        let attributes = if is_dir {
            file_attributes | FILE_ATTRIBUTE_DIRECTORY
        } else {
            let a = (file_attributes | FILE_ATTRIBUTE_ARCHIVE) & !FILE_ATTRIBUTE_DIRECTORY;
            if a == FILE_ATTRIBUTE_ARCHIVE {
                a | FILE_ATTRIBUTE_NORMAL
            } else {
                a
            }
        };

        let now = filetime_now();
        let id = state.next_id;
        state.next_id += 1;
        let index_number = state.next_index;
        state.next_index += 1;

        state.nodes.insert(
            id,
            Node {
                name: original,
                is_dir,
                attributes,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
                index_number,
                data: Vec::new(),
                size: 0,
            },
        );
        state.by_path.insert(key, id);

        *file_info.as_mut() = state.get(id).file_info();
        Ok(id)
    }

    fn close(&self, _context: Self::FileContext) {}

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        if !FspCleanupFlags::FspCleanupDelete.is_flagged(flags) {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let id = *context;
        let Some(node) = state.nodes.get(&id) else {
            return;
        };
        let key = canon(&node.name);
        if node.is_dir && state.has_children(&key) {
            return;
        }
        state.by_path.remove(&key);
        state.nodes.remove(&id);
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let state = self.state.lock().unwrap();
        let node = state.get(*context);
        if offset >= node.size {
            return Err(nt(STATUS_END_OF_FILE));
        }
        let plain = self.decrypt(node);
        let end = (offset + buffer.len() as u64).min(node.size);
        let len = (end - offset) as usize;
        buffer[..len].copy_from_slice(&plain[offset as usize..offset as usize + len]);
        Ok(len as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let mut state = self.state.lock().unwrap();
        let id = *context;
        let mut plain = self.decrypt(state.get(id));
        let size = plain.len() as u64;
        let start = if write_to_eof { size } else { offset };

        let written;
        if constrained_io {
            if start >= size {
                *file_info = state.get(id).file_info();
                return Ok(0);
            }
            let end = (start + buffer.len() as u64).min(size);
            let len = (end - start) as usize;
            plain[start as usize..start as usize + len].copy_from_slice(&buffer[..len]);
            written = len;
        } else {
            let end = start + buffer.len() as u64;
            if end > self.max_file_size {
                return Err(nt(STATUS_DISK_FULL));
            }
            if end as usize > plain.len() {
                plain.resize(end as usize, 0);
            }
            plain[start as usize..end as usize].copy_from_slice(buffer);
            written = buffer.len();
        }

        self.store(state.get_mut(id), plain);
        *file_info = state.get(id).file_info();
        Ok(written as u32)
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if let Some(id) = context {
            let state = self.state.lock().unwrap();
            *file_info = state.get(*id).file_info();
        }
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let state = self.state.lock().unwrap();
        *file_info = state.get(*context).file_info();
        Ok(())
    }

    fn get_security(
        &self,
        _context: &Self::FileContext,
        _security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        Ok(0)
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock().unwrap();
        let id = *context;
        {
            let node = state.get_mut(id);
            if file_attributes != INVALID_FILE_ATTRIBUTES && file_attributes != 0 {
                node.attributes = file_attributes;
            }
            if creation_time != 0 {
                node.creation_time = creation_time;
            }
            if last_access_time != 0 {
                node.last_access_time = last_access_time;
            }
            if last_write_time != 0 {
                node.last_write_time = last_write_time;
            }
            if last_change_time != 0 {
                node.change_time = last_change_time;
            }
        }
        *file_info = state.get(id).file_info();
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if new_size > self.max_file_size {
            return Err(nt(STATUS_DISK_FULL));
        }
        let mut state = self.state.lock().unwrap();
        let id = *context;
        let current = state.get(id).size;
        if set_allocation_size {
            // Allocation is derived from the logical size here; only a shrink below the current
            // size is observable, so clamp to it and leave a pure grow as a no-op.
            if new_size < current {
                let mut plain = self.decrypt(state.get(id));
                plain.truncate(new_size as usize);
                self.store(state.get_mut(id), plain);
            }
        } else if new_size != current {
            let mut plain = self.decrypt(state.get(id));
            plain.resize(new_size as usize, 0);
            self.store(state.get_mut(id), plain);
        }
        *file_info = state.get(id).file_info();
        Ok(())
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock().unwrap();
        let id = *context;
        let now = filetime_now();
        {
            let node = state.get_mut(id);
            node.data.clear();
            node.size = 0;
            if replace_file_attributes {
                node.attributes = file_attributes | FILE_ATTRIBUTE_ARCHIVE;
            } else {
                node.attributes |= file_attributes | FILE_ATTRIBUTE_ARCHIVE;
            }
            node.last_write_time = now;
            node.change_time = now;
        }
        *file_info = state.get(id).file_info();
        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if !delete_file {
            return Ok(());
        }
        let state = self.state.lock().unwrap();
        let node = state.get(*context);
        if node.is_dir && state.has_children(&canon(&node.name)) {
            return Err(nt(STATUS_DIRECTORY_NOT_EMPTY));
        }
        Ok(())
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock().unwrap();
        let id = *context;
        let new_original = new_file_name.to_string_lossy();
        let new_key = canon(&new_original);

        if let Some(other) = state.id_of(&new_key) {
            if other != id {
                if !replace_if_exists {
                    return Err(nt(STATUS_OBJECT_NAME_COLLISION));
                }
                state.by_path.remove(&new_key);
                state.nodes.remove(&other);
            }
        }

        let old_original = state.get(id).name.clone();
        let old_key = canon(&old_original);
        let child_prefix = format!("{old_key}\\");

        // Move the node and every descendant (a directory rename carries its whole subtree).
        let affected: Vec<(u64, String)> = state
            .nodes
            .iter()
            .filter(|(_, n)| {
                let c = canon(&n.name);
                c == old_key || c.starts_with(&child_prefix)
            })
            .map(|(nid, n)| (*nid, n.name.clone()))
            .collect();

        for (nid, original) in affected {
            let suffix = &original[old_original.len()..];
            let moved = format!("{new_original}{suffix}");
            state.by_path.remove(&canon(&original));
            state.by_path.insert(canon(&moved), nid);
            state.get_mut(nid).name = moved;
        }
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let state = self.state.lock().unwrap();
        let dir_id = *context;
        let dir_key = canon(&state.get(dir_id).name);
        if !state.get(dir_id).is_dir {
            return Err(nt(STATUS_NOT_A_DIRECTORY));
        }

        // Ordered listing: `.`, `..` (non-root), then direct children by case-folded name.
        let mut entries: Vec<(Vec<u16>, FileInfo)> = Vec::new();
        if let Some(parent_key) = parent_canon(&dir_key) {
            entries.push((vec![b'.' as u16], state.get(dir_id).file_info()));
            if let Some(parent_id) = state.id_of(&parent_key) {
                entries.push((
                    vec![b'.' as u16, b'.' as u16],
                    state.get(parent_id).file_info(),
                ));
            }
        }

        let mut kids: Vec<(String, u64)> = state
            .nodes
            .iter()
            .filter(|(_, n)| {
                let c = canon(&n.name);
                c != dir_key && parent_canon(&c).as_deref() == Some(dir_key.as_str())
            })
            .map(|(nid, n)| (basename(&n.name).to_string(), *nid))
            .collect();
        kids.sort_by_key(|k| k.0.to_uppercase());
        for (name, nid) in kids {
            entries.push((name.encode_utf16().collect(), state.get(nid).file_info()));
        }

        let mut start = 0;
        if let Some(m) = marker.inner_as_cstr() {
            if let Some(pos) = entries.iter().position(|(n, _)| n.as_slice() == m.as_slice()) {
                start = pos + 1;
            }
        }

        let mut cursor = 0u32;
        let mut dir_info: DirInfo<255> = DirInfo::new();
        for (name, info) in &entries[start..] {
            dir_info.reset();
            *dir_info.file_info_mut() = info.clone();
            dir_info.set_name_raw(name.as_slice())?;
            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }
        DirInfo::<255>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        let state = self.state.lock().unwrap();
        let used: u64 = state
            .nodes
            .values()
            .map(|n| round_up(n.size as usize, SECTOR_SIZE) as u64)
            .sum();
        out_volume_info.total_size = self.capacity;
        out_volume_info.free_size = self.capacity.saturating_sub(used);
        let label: std::ffi::OsString =
            std::os::windows::prelude::OsStringExt::from_wide(&state.label);
        out_volume_info.set_volume_label(&label);
        Ok(())
    }
}

/// Mounts the Clave Disk at `mount_point` (e.g. `X:`) on a dedicated thread and keeps it live for
/// the process. Returns a channel that yields the mount result once: `Ok(())` when the volume is
/// serving, or `Err` describing why WinFsp could not mount (not installed, drive in use, …). The
/// worker thread owns the WinFsp init token and host, so the mount survives until the daemon exits.
pub fn spawn_clave_disk(
    mount_point: String,
    dek: Dek,
    capacity: u64,
) -> Receiver<Result<(), String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let init = match winfsp::winfsp_init() {
            Ok(init) => init,
            Err(e) => {
                let _ = tx.send(Err(format!("WinFsp runtime unavailable: {e}")));
                return;
            }
        };

        let mut params = VolumeParams::new();
        params
            .sector_size(SECTOR_SIZE as u16)
            .sectors_per_allocation_unit(1)
            .volume_creation_time(filetime_now())
            .volume_serial_number((filetime_now() / (10_000 * 1000)) as u32)
            .file_info_timeout(u32::MAX)
            .case_sensitive_search(false)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(false)
            .reparse_points(false)
            .named_streams(false);
        params.filesystem_name("ClaveDisk");

        let fs = ClaveDiskFs::new(&dek, capacity);
        let mut host: FileSystemHost<ClaveDiskFs> = match FileSystemHost::new(params, fs) {
            Ok(host) => host,
            Err(e) => {
                let _ = tx.send(Err(format!("host create failed: {e}")));
                return;
            }
        };
        if let Err(e) = host.mount(mount_point.as_str()) {
            let _ = tx.send(Err(format!("mount {mount_point} failed: {e}")));
            return;
        }
        if let Err(e) = host.start() {
            let _ = tx.send(Err(format!("dispatcher start failed: {e}")));
            return;
        }

        let _ = tx.send(Ok(()));
        // Own the init token and host for the process lifetime; dropping either would unmount.
        let _keep_alive = (init, host);
        loop {
            std::thread::park();
        }
    });
    rx
}

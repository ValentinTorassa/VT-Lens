use std::fmt;

#[derive(Clone, Debug, Default)]
pub struct ProcessRow {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub state: String,
    pub rss_kb: u64,
    pub threads: u32,
    pub socket_count: usize,
    /// Real UID (/proc/<pid>/status on Linux, libproc on macOS); only its
    /// class leaves the app.
    pub uid: Option<u32>,
}

impl ProcessRow {
    pub fn rss_mb(&self) -> f64 {
        self.rss_kb as f64 / 1024.0
    }

    #[allow(dead_code)]
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, self.pid)
    }
}

#[derive(Clone, Debug)]
pub struct SocketOwner {
    pub pid: u32,
    pub process: String,
}

/// Identifies one socket within a snapshot.
///
/// Linux names a socket by its inode: `/proc/<pid>/fd/N -> socket:[inode]`
/// links the process to its row in `/proc/net/tcp`. macOS has no such table;
/// `lsof` reports each socket as a file descriptor of its owning process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketId {
    Inode(u64),
    Fd { pid: u32, fd: u32 },
}

impl fmt::Display for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inode(inode) => write!(f, "inode {inode}"),
            Self::Fd { fd, .. } => write!(f, "fd {fd}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NetRow {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub tx_queue: u64,
    pub rx_queue: u64,
    pub socket_id: SocketId,
    pub owner: Option<SocketOwner>,
}

impl NetRow {
    pub fn owner_label(&self) -> String {
        self.owner
            .as_ref()
            .map(|owner| format!("{} ({})", owner.process, owner.pid))
            .unwrap_or_else(|| "unknown".to_string())
    }
}

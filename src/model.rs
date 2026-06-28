#[derive(Clone, Debug, Default)]
pub struct ProcessRow {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub state: String,
    pub rss_kb: u64,
    pub threads: u32,
    pub socket_count: usize,
}

impl ProcessRow {
    pub fn rss_mb(&self) -> f64 {
        self.rss_kb as f64 / 1024.0
    }

    pub fn label(&self) -> String {
        format!("{} ({})", self.name, self.pid)
    }
}

#[derive(Clone, Debug)]
pub struct SocketOwner {
    pub pid: u32,
    pub process: String,
}

#[derive(Clone, Debug)]
pub struct NetRow {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub tx_queue: u64,
    pub rx_queue: u64,
    pub inode: String,
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

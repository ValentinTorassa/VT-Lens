pub mod net_poller;
pub mod proc_poller;

pub use net_poller::{read_connections, socket_owners};
pub use proc_poller::read_processes;

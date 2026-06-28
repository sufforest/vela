//! Background maintenance tasks that keep unbounded-growth state in
//! check: the short-TTL dedup-cache pruner and the device-list retention
//! pruner. Future periodic housekeeping (other never-pruned column
//! families) belongs here.

pub mod dedup_pruner;
pub mod device_list_pruner;

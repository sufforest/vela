//! Background maintenance tasks that keep unbounded-growth state in
//! check. Currently just the dedup-cache pruner; future periodic
//! housekeeping (e.g. other never-pruned column families) belongs here.

pub mod dedup_pruner;

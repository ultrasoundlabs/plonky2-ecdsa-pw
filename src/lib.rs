#![allow(clippy::needless_range_loop)]
// #![cfg_attr(not(test), no_std)]
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

extern crate alloc;

pub mod curve;
pub mod gadgets;

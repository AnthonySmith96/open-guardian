//! Reusable Open-Guardian security primitives.
//!
//! The proxy binary is one consumer. Other local applications can depend on
//! the crate without embedding the HTTP server.

pub mod secrets;

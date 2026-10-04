//! # olo-gate
//!
//! A tiny guard for AI coding agents. It classifies what an agent is about to do (shell commands,
//! file edits, MCP tool calls), masks secrets, and computes the *real* effect of risky git and `rm`
//! commands before a person decides.
//!
//! It is a guard against slips and unsupervised actions, **not a sandbox**: an agent with terminal
//! access acts with your permissions. See `docs/threat-model.md`.

pub mod config;
pub mod effect;
pub mod hook;
pub mod rules;

pub use rules::{assess, redact, Assessment, Risk};

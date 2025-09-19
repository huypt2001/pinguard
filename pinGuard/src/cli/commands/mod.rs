//! Command handlers for the CLI interface

pub mod scan;
pub mod fix;
pub mod report;
pub mod config;
pub mod database;
pub mod cve;
pub mod schedule;
pub mod completion;

use crate::core::errors::PinGuardResult;
pub mod cli;
pub mod config;
pub mod discover;
pub mod doctor;
pub mod executor;
pub mod fs;
pub mod planner;
pub mod privilege;
pub mod render;
pub mod selectors;
pub mod state;

use anyhow::Result;

pub fn run() -> Result<()> {
    cli::run()
}

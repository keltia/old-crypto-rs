//! Configuration loader for kl7ctl.

use kl_7::Kl7Config;
use std::{error::Error, fs, path::Path};

/// Load a KL-7 configuration from a file path, or default to reference configuration.
pub fn load_config(path: Option<&Path>) -> Result<Kl7Config, Box<dyn Error>> {
    match path {
        Some(p) => {
            let content = fs::read_to_string(p)?;
            let config = Kl7Config::from_yaml(&content)?;
            Ok(config)
        }
        None => Ok(Kl7Config::uss_beagle()),
    }
}

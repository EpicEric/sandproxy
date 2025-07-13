use std::{net::IpAddr, path::PathBuf, str::FromStr};

use color_eyre::eyre::OptionExt;
use serde::Deserialize;
use serde_with::DeserializeFromStr;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub address: Option<IpAddr>,
    pub port: u16,
    pub accounts: Vec<ConfigAccount>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigAccount {
    pub private_key_path: PathBuf,
    pub reverse_proxies: Vec<ConfigReverseProxy>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigReverseProxy {
    pub host: String,
    pub port: u16,
    pub proxies: Vec<ConfigProxy>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigProxy {
    pub user: String,
    pub alias: TcpAlias,
}

#[derive(Debug, DeserializeFromStr)]
pub struct TcpAlias(pub String, pub u16);

impl FromStr for TcpAlias {
    type Err = color_eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (left, right) = s.rsplit_once(':').ok_or_eyre("missing : separator")?;
        Ok(TcpAlias(left.to_owned(), right.parse()?))
    }
}

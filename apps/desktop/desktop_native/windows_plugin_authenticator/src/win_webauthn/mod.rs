mod com;
mod util;

use std::{error::Error, fmt::Display};

use windows::core::GUID;

struct Plugin {
    clsid: GUID,
}

pub struct Clsid(GUID);

impl TryFrom<&str> for Clsid {
    type Error = WinWebAuthnError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Remove hyphens and parse as hex
        let clsid_clean = value.replace("-", "").replace("{", "").replace("}", "");
        if clsid_clean.len() != 32 {
            return Err(WinWebAuthnError::new(
                ErrorKind::Serialization,
                Some("Invalid CLSID format"),
            ));
        }

        // Convert to u128 and create GUID
        let clsid_u128 = u128::from_str_radix(&clsid_clean, 16).map_err(|err| {
            WinWebAuthnError::with_cause(
                ErrorKind::Serialization,
                Some("Failed to parse CLSID as hex"),
                err,
            )
        })?;

        let clsid = Clsid(GUID::from_u128(clsid_u128));
        Ok(clsid)
    }
}

struct WebAuthnPlugin;

impl WebAuthnPlugin {
    /// Registers a COM server with Windows.
    ///
    /// This only needs to be called on installation of your application.
    pub fn register(clsid: &Clsid) -> Result<(), WinWebAuthnError> {
        com::register_server(&clsid.0);
        Ok(())
    }
}

#[derive(Debug)]
pub struct WinWebAuthnError {
    kind: ErrorKind,
    description: Option<String>,
    cause: Option<Box<dyn std::error::Error>>,
}

impl WinWebAuthnError {
    pub(crate) fn new(kind: ErrorKind, description: Option<&str>) -> Self {
        Self {
            kind,
            description: description.map(|s| s.to_string()),
            cause: None,
        }
    }

    pub(crate) fn with_cause<E: std::error::Error + 'static>(
        kind: ErrorKind,
        description: Option<&str>,
        cause: E,
    ) -> Self {
        let cause: Box<dyn std::error::Error> = Box::new(cause);
        Self {
            kind,
            description: description.map(|s| s.to_string()),
            cause: Some(cause),
        }
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    DllLoad,
    Serialization,
    WindowsInternal,
}

impl Display for WinWebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self.kind {
            ErrorKind::Serialization => "Failed to serialize data",
            ErrorKind::DllLoad => "Failed to load function from DLL",
            ErrorKind::WindowsInternal => "A Windows error occurred",
        };
        f.write_str(msg)?;
        if let Some(d) = &self.description {
            write!(f, ": {d}")?;
        }
        if let Some(e) = &self.cause {
            write!(f, ". Caused by: {e}")?;
        }
        Ok(())
    }
}

impl Error for WinWebAuthnError {}

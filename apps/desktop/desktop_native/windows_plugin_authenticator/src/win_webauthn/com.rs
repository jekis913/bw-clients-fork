//! Functions for interacting with Windows COM.

use std::ptr;

use windows::{core::GUID, Win32::System::Com::*};

use crate::win_webauthn::{ErrorKind, WinWebAuthnError};

#[implement(IClassFactory)]
pub struct Factory;

pub(super) fn register_server(clsid: &GUID) -> Result<(), WinWebAuthnError> {
    static FACTORY: windows::core::StaticComObject<Factory> = Factory.into_static();
    unsafe {
        CoRegisterClassObject(
            ptr::from_ref(clsid),
            FACTORY.as_interface_ref(),
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE,
        )
    }
    .map_err(|err| {
        WinWebAuthnError::with_cause(
            ErrorKind::WindowsInternal,
            Some("Couldn't register the COM library with Windows"),
            err,
        )
    })?;
    Ok(())
}

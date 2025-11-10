
/// Initializes the COM library for use on the calling thread,
/// and registers + sets the security values.
pub fn initialize_com_library() -> std::result::Result<(), String> {
    let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };

    if result.is_err() {
        return Err(format!(
            "Error: couldn't initialize the COM library\n{}",
            result.message()
        ));
    }

    match unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
    } {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "Error: couldn't initialize COM security\n{}",
            e.message()
        )),
    }
}
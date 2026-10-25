#[repr(C)]
pub struct Error {
    pub code: i32,
    str: Option<core::ptr::NonNull<i8>>, // strdup("string") from C/C++
}

impl Drop for Error {
    fn drop(&mut self) {
        // libc's own signature: the standard library links this `free` too, and rustc warns about a
        // declaration of it with any other, however compatible the ABI.
        extern "C" {
            fn free(ptr: *mut core::ffi::c_void);
        }
        if let Some(str) = self.str.take() {
            unsafe { free(str.as_ptr().cast()) };
        }
    }
}

impl From<&Error> for String {
    fn from(status: &Error) -> Self {
        if let Some(str) = status.str {
            let c_str = unsafe { std::ffi::CStr::from_ptr(str.as_ptr() as *const _) };
            String::from(c_str.to_str().unwrap_or("unintelligible"))
        } else {
            format!("gpu_api::Error #{}", status.code)
        }
    }
}

impl From<Error> for String {
    fn from(status: Error) -> Self {
        String::from(&status)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

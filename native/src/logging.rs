use crate::{c_char, c_void};

#[repr(C)]
pub struct LogRecord {
    level: LogLevel,
    message: *const c_char,
    target: *const c_char,
    file: *const c_char,
    line: u32,
}

#[repr(C)]
#[allow(clippy::enum_variant_names)]
pub enum LogLevel {
    LogLevelError,
    LogLevelWarn,
    LogLevelInfo,
    LogLevelDebug,
    LogLevelTrace,
}

impl From<log::Level> for LogLevel {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => Self::LogLevelError,
            log::Level::Warn => Self::LogLevelWarn,
            log::Level::Info => Self::LogLevelInfo,
            log::Level::Debug => Self::LogLevelDebug,
            log::Level::Trace => Self::LogLevelTrace,
        }
    }
}

#[repr(C)]
pub struct Logger {
    data: *mut c_void,
    enabled: Option<unsafe extern "C" fn(data: *mut c_void, level: LogLevel) -> cty::c_int>,
    log: Option<unsafe extern "C" fn(data: *mut c_void, message: &LogRecord)>,
    flush: Option<unsafe extern "C" fn(data: *mut c_void)>,
}

unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        match self.enabled {
            Some(enabled) => unsafe { enabled(self.data, metadata.level().into()) != 0 },
            None => true,
        }
    }

    fn log(&self, record: &log::Record) {
        let log = match self.log {
            Some(log) => log,
            None => return,
        };

        let mut message = String::with_capacity(100);
        let res = core::fmt::write(&mut message, *record.args());
        if res.is_err() && message.is_empty() {
            return;
        }

        let mut message = message.into_bytes();
        message.push(b'\0');

        let target = record.target();
        let mut raw_target = Vec::with_capacity(target.len() + 1);
        raw_target.extend_from_slice(target.as_bytes());
        raw_target.push(b'\0');

        let file = record.file().map(|file| {
            let mut raw_file = Vec::with_capacity(file.len() + 1);
            raw_file.extend_from_slice(file.as_bytes());
            raw_file.push(b'\0');
            raw_file
        });

        let message = LogRecord {
            level: record.level().into(),
            message: message.as_ptr(),
            target: raw_target.as_ptr(),
            file: file.as_ref().map_or(core::ptr::null(), |f| f.as_ptr()),
            line: record.line().unwrap_or(0),
        };

        unsafe {
            log(self.data, &message);
        }
    }

    fn flush(&self) {
        if let Some(flush) = self.flush {
            unsafe { flush(self.data) }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn set_logger(logger: *mut Logger) -> bool {
    log::set_max_level(log::LevelFilter::Trace);
    log::set_logger(&*logger).is_ok()
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn set_default_logger() -> bool {
    env_logger::try_init().is_ok()
}

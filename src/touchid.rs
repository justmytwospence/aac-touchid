//! Human-presence approval with Touch ID or Apple Watch.
//!
//! Uses LocalAuthentication's `deviceOwnerAuthenticationWithBiometricsOrCompanion`
//! policy with the password fallback hidden: nothing a process can type or
//! click produces an approval, only a finger on the sensor or a Watch
//! double-press.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Denied,
    TimedOut,
    /// Biometrics unavailable (none enrolled, lid closed without Watch, ...).
    Unavailable,
}

/// Ask for approval with the system sheet. macOS words it `"<program>" is
/// trying to <reason>.` and titles it with the program's file name, so the
/// service runs from a binary named `Bitwarden` (see the README).
pub fn confirm_blocking(reason: &str, timeout: Duration) -> Outcome {
    imp::confirm_blocking(reason, timeout)
}

/// Whether a Touch ID (or Watch) approval could be shown right now.
pub fn available() -> bool {
    imp::availability().is_ok()
}

/// Like [`available`], with LocalAuthentication's reason when it is not.
pub fn availability() -> Result<(), String> {
    imp::availability()
}

/// Whether the login session's screen is locked (or there is no GUI session).
pub fn screen_locked() -> bool {
    imp::screen_locked()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Outcome;
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, Bool};
    use objc2_foundation::{NSDictionary, NSError, NSNumber, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn availability() -> Result<(), String> {
        // SAFETY: plain LocalAuthentication call on a context owned here.
        unsafe {
            LAContext::new()
                .canEvaluatePolicy_error(
                    LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrCompanion,
                )
                .map_err(|e| format!("LAError {}: {}", e.code(), e.localizedDescription()))
        }
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> *mut NSDictionary<NSString, AnyObject>;
    }

    pub fn screen_locked() -> bool {
        // SAFETY: the function follows the Create rule: a null result or a
        // +1 retained dictionary, which `Retained::from_raw` takes over.
        unsafe {
            let Some(dict) = Retained::from_raw(CGSessionCopyCurrentDictionary()) else {
                return true;
            };
            let key = NSString::from_str("CGSSessionScreenIsLocked");
            let Some(v) = dict.objectForKey(&key) else {
                return false;
            };
            let n: Option<&NSNumber> = v.downcast_ref();
            n.is_some_and(|n| n.boolValue())
        }
    }

    pub fn confirm_blocking(reason: &str, timeout: Duration) -> Outcome {
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrCompanion;
        // SAFETY: plain LocalAuthentication calls on a context owned by this thread.
        unsafe {
            let ctx = LAContext::new();
            if let Err(e) = ctx.canEvaluatePolicy_error(policy) {
                // -8 lockout (Mac password needed), -7 nothing enrolled,
                // -6 no sensor, -11 no Watch nearby.
                tracing::info!(
                    "touch id unavailable (LAError {}: {})",
                    e.code(),
                    e.localizedDescription()
                );
                return Outcome::Unavailable;
            }
            // An empty fallback title hides the "Use Password" button.
            ctx.setLocalizedFallbackTitle(Some(&NSString::from_str("")));
            let (tx, rx) = mpsc::channel::<(bool, isize)>();
            let block = RcBlock::new(move |ok: Bool, err: *mut NSError| {
                let code = if err.is_null() { 0 } else { (*err).code() };
                let _ = tx.send((ok.as_bool(), code));
            });
            ctx.evaluatePolicy_localizedReason_reply(policy, &NSString::from_str(reason), &block);
            match rx.recv_timeout(timeout) {
                Ok((true, _)) => Outcome::Approved,
                Ok((false, code)) => {
                    tracing::info!("touch id declined (LAError {code})");
                    Outcome::Denied
                }
                Err(_) => {
                    // Dismiss the sheet; the reply then fires with AppCancel.
                    ctx.invalidate();
                    let _ = rx.recv_timeout(Duration::from_secs(5));
                    Outcome::TimedOut
                }
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::Outcome;
    use std::time::Duration;

    pub fn confirm_blocking(_reason: &str, _timeout: Duration) -> Outcome {
        Outcome::Unavailable
    }

    pub fn availability() -> Result<(), String> {
        Err("not macOS".to_string())
    }

    pub fn screen_locked() -> bool {
        false
    }
}

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

/// Ask for approval. `reason` completes the sentence
/// `"aac-touchid" is trying to <reason>.`
pub async fn confirm(reason: String, timeout: Duration) -> Outcome {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(imp::confirm_blocking(&reason, timeout));
    });
    rx.await.unwrap_or(Outcome::Denied)
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Outcome;
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn confirm_blocking(reason: &str, timeout: Duration) -> Outcome {
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrCompanion;
        // SAFETY: plain LocalAuthentication calls on a context owned by this thread.
        unsafe {
            let ctx = LAContext::new();
            if ctx.canEvaluatePolicy_error(policy).is_err() {
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
}

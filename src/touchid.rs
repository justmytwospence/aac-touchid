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

/// Ask for approval. macOS words the sheet `"<program>" is trying to <reason>.`
/// With `as_name`, the sheet is shown by a link to this binary named `as_name`
/// (the requesting agent), so that name replaces the program name.
pub async fn confirm(as_name: Option<&str>, reason: String, timeout: Duration) -> Outcome {
    if let Some(name) = as_name {
        match prompt_via_link(name, &reason, timeout).await {
            Ok(outcome) => return outcome,
            Err(e) => tracing::warn!("named prompt failed ({e}); using the plain one"),
        }
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(imp::confirm_blocking(&reason, timeout));
    });
    rx.await.unwrap_or(Outcome::Denied)
}

/// For the hidden `prompt` subcommand.
pub fn prompt_exit_code(reason: &str, timeout: Duration) -> u8 {
    match imp::confirm_blocking(reason, timeout) {
        Outcome::Approved => 0,
        Outcome::Denied => 10,
        Outcome::TimedOut => 11,
        Outcome::Unavailable => 12,
    }
}

/// A file name macOS can show: no path separators or control characters.
pub fn display_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != ':')
        .take(60)
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        "agent".to_string()
    } else {
        cleaned
    }
}

async fn prompt_via_link(name: &str, reason: &str, timeout: Duration) -> std::io::Result<Outcome> {
    let exe = std::env::current_exe()?;
    let dir = crate::storage::state_dir()?.join("prompts");
    std::fs::create_dir_all(&dir)?;
    let link = dir.join(display_file_name(name));
    let _ = std::fs::remove_file(&link);
    if std::fs::hard_link(&exe, &link).is_err() {
        std::fs::copy(&exe, &link)?;
    }
    let status = tokio::process::Command::new(&link)
        .arg("prompt")
        .arg("--timeout")
        .arg(timeout.as_secs().to_string())
        .arg(reason)
        .kill_on_drop(true)
        .status()
        .await;
    let _ = std::fs::remove_file(&link);
    Ok(match status?.code() {
        Some(0) => Outcome::Approved,
        Some(11) => Outcome::TimedOut,
        Some(12) => Outcome::Unavailable,
        _ => Outcome::Denied,
    })
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

#[cfg(test)]
mod tests {
    use super::display_file_name;

    #[test]
    fn display_names_are_safe_file_names() {
        assert_eq!(
            display_file_name("pi \u{b7} homelab (nuc)"),
            "pi \u{b7} homelab (nuc)"
        );
        assert_eq!(display_file_name("../../etc/passwd"), "etcpasswd");
        assert_eq!(display_file_name("a:b\nc"), "abc");
        assert_eq!(display_file_name("   "), "agent");
        assert_eq!(display_file_name(&"x".repeat(100)).len(), 60);
    }
}

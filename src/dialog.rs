//! Native macOS master-password dialog (AppleScript `display dialog`).

use std::process::Command;
use std::time::Duration;

use zeroize::Zeroizing;

const SCRIPT: &str = r#"on run argv
  set r to display dialog (item 1 of argv) default answer "" with hidden answer with title "Bitwarden agent access" with icon caution buttons {"Cancel", "Unlock"} default button "Unlock" cancel button "Cancel" giving up after (item 2 of argv as integer)
  if gave up of r then error number -128
  return text returned of r
end run"#;

/// Ask for the master password. `None` if cancelled, timed out or empty.
pub async fn ask_master_password(message: String, timeout: Duration) -> Option<Zeroizing<String>> {
    tokio::task::spawn_blocking(move || {
        let out = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(SCRIPT)
            .arg(message)
            .arg(timeout.as_secs().to_string())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let mut text = Zeroizing::new(String::from_utf8_lossy(&out.stdout).into_owned());
        while text.ends_with('\n') {
            text.pop();
        }
        (!text.is_empty()).then_some(text)
    })
    .await
    .ok()
    .flatten()
}

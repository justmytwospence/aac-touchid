//! The approval panel: a native alert with labelled rows, a countdown, scope
//! buttons and Deny by default, shown by a child process of the listener
//! (`aac-touchid prompt`). Allow still needs Touch ID: the child asks for it
//! after the click. The decision comes back on a pipe only the listener holds.

use std::process::{ExitCode, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::warn;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    pub label: String,
    pub minutes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    pub title: String,
    pub rows: Vec<Row>,
    pub note: Option<String>,
    /// Allow buttons, in order, after Deny.
    pub choices: Vec<Choice>,
    /// Index into `choices` of the button Return presses.
    pub default_choice: Option<usize>,
    /// Completes "Bitwarden is trying to ..." on the Touch ID sheet.
    pub touch_reason: String,
    pub timeout_secs: u64,
    /// Placeholder of a secure text field the human fills in (`ask:`).
    pub input: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Approved {
        choice: usize,
        #[serde(default)]
        value: Option<String>,
    },
    Denied,
    TimedOut,
    Unavailable,
}

/// Show the panel in a child process and wait for its decision.
pub async fn ask(prompt: &Prompt) -> Decision {
    match run_child(prompt).await {
        Ok(d) => d,
        Err(e) => {
            warn!("approval panel failed: {e}");
            Decision::Denied
        }
    }
}

async fn run_child(prompt: &Prompt) -> Result<Decision, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut child = Command::new(exe)
        .arg("prompt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("start panel: {e}"))?;
    let body = Zeroizing::new(serde_json::to_vec(prompt).map_err(|e| e.to_string())?);
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&body)
            .await
            .map_err(|e| format!("write panel: {e}"))?;
    }
    let mut stdout = child.stdout.take().ok_or("no panel output")?;
    let mut buf = Zeroizing::new(Vec::new());
    let read = tokio::time::timeout(
        Duration::from_secs(prompt.timeout_secs + 10),
        stdout.read_to_end(&mut buf),
    )
    .await;
    match read {
        Err(_) => {
            let _ = child.kill().await;
            return Ok(Decision::TimedOut);
        }
        Ok(Err(e)) => return Err(format!("read panel: {e}")),
        Ok(Ok(_)) => {}
    }
    let _ = child.wait().await;
    let line = buf.split(|b| *b == b'\n').next().unwrap_or_default();
    serde_json::from_slice(line).map_err(|_| "unreadable panel reply".to_string())
}

/// The `prompt` subcommand: read a [`Prompt`] on stdin, print a [`Decision`].
pub fn child_main() -> ExitCode {
    use std::io::Read;
    let mut input = Zeroizing::new(Vec::new());
    if std::io::stdin().read_to_end(&mut input).is_err() {
        println!("{{\"decision\":\"denied\"}}");
        return ExitCode::FAILURE;
    }
    let Ok(prompt) = serde_json::from_slice::<Prompt>(&input) else {
        println!("{{\"decision\":\"denied\"}}");
        return ExitCode::FAILURE;
    };
    let decision = imp::run(&prompt);
    match serde_json::to_string(&decision) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{Decision, Prompt};

    pub fn run(_p: &Prompt) -> Decision {
        Decision::Unavailable
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::cell::Cell;
    use std::ptr::NonNull;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use block2::RcBlock;
    use objc2::MainThreadMarker;
    use objc2::rc::Retained;
    use objc2_app_kit::{
        NSAlert, NSAlertFirstButtonReturn, NSApplication, NSApplicationActivationPolicy, NSButton,
        NSColor, NSFloatingWindowLevel, NSFont, NSGridCellPlacement, NSGridView, NSImage,
        NSModalResponseAbort, NSSecureTextField, NSSound, NSTextField, NSView,
        NSWindowCollectionBehavior,
    };
    use objc2_foundation::{NSArray, NSRunLoop, NSRunLoopCommonModes, NSSize, NSString, NSTimer};

    use super::{Decision, Prompt};
    use crate::touchid::{self, Outcome};

    const ARM_DELAY: Duration = Duration::from_secs(1);

    fn clock(left: Duration) -> String {
        let s = left.as_secs();
        format!("{}:{:02}", s / 60, s % 60)
    }

    pub fn run(p: &Prompt) -> Decision {
        if let Err(e) = touchid::availability() {
            eprintln!("aac-touchid prompt: Touch ID unavailable ({e})");
            return Decision::Unavailable;
        }
        let Some(mtm) = MainThreadMarker::new() else {
            return Decision::Denied;
        };
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        let deadline = Instant::now() + Duration::from_secs(p.timeout_secs);
        if let Some(sound) = NSSound::soundNamed(&NSString::from_str("Glass")) {
            sound.play();
        }
        let mut notice = String::new();
        while Instant::now() < deadline {
            match pass(mtm, &app, p, deadline, &notice) {
                Pass::Done(d) => return d,
                Pass::Again(n) => notice = n,
            }
        }
        Decision::TimedOut
    }

    enum Pass {
        Done(Decision),
        Again(String),
    }

    fn pass(
        mtm: MainThreadMarker,
        app: &Retained<NSApplication>,
        p: &Prompt,
        deadline: Instant,
        notice: &str,
    ) -> Pass {
        let started = Instant::now();
        let alert = NSAlert::new(mtm);
        alert.setMessageText(&NSString::from_str(&p.title));
        let mut info = String::new();
        if !notice.is_empty() {
            info.push_str(notice);
            info.push_str("\n\n");
        }
        info.push_str(p.note.as_deref().unwrap_or(""));
        alert.setInformativeText(&NSString::from_str(&info));
        if let Some(icon) = NSImage::imageWithSystemSymbolName_accessibilityDescription(
            &NSString::from_str("key.fill"),
            None,
        ) {
            // SAFETY: a plain image set on an alert we own.
            unsafe { alert.setIcon(Some(&icon)) };
        }

        // Rows of the accessory grid.
        let mut rows: Vec<Retained<NSArray<NSView>>> = Vec::new();
        let mut add_row = |label: &str, value: &NSView| {
            let l = NSTextField::labelWithString(&NSString::from_str(label), mtm);
            l.setTextColor(Some(&NSColor::secondaryLabelColor()));
            let lv: &NSView = &l;
            rows.push(NSArray::from_slice(&[lv, value]));
        };
        for r in &p.rows {
            let v = NSTextField::wrappingLabelWithString(&NSString::from_str(&r.value), mtm);
            v.setFont(Some(&NSFont::boldSystemFontOfSize(13.0)));
            v.setSelectable(true);
            v.setPreferredMaxLayoutWidth(320.0);
            let vv: &NSView = &v;
            add_row(&r.label, vv);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let countdown = NSTextField::labelWithString(&NSString::from_str(&clock(left)), mtm);
        {
            let cv: &NSView = &countdown;
            add_row("Answer within", cv);
        }
        let field: Option<Retained<NSSecureTextField>> = p.input.as_ref().map(|hint| {
            let f = NSSecureTextField::new(mtm);
            f.setPlaceholderString(Some(&NSString::from_str(hint)));
            f.setFrameSize(NSSize::new(320.0, 22.0));
            f
        });
        if let Some(f) = &field {
            let fv: &NSView = f;
            add_row("Value", fv);
        }
        let row_refs: Vec<&NSArray<NSView>> = rows.iter().map(|r| &**r).collect();
        let grid = NSGridView::gridViewWithViews(&NSArray::from_slice(&row_refs), mtm);
        grid.columnAtIndex(0)
            .setXPlacement(NSGridCellPlacement::Trailing);
        grid.setRowSpacing(6.0);
        let gv: &NSView = &grid;
        gv.setFrameSize(gv.fittingSize());
        alert.setAccessoryView(Some(gv));

        // Buttons: Deny first (Esc), then the Allow choices, disarmed.
        let deny = alert.addButtonWithTitle(&NSString::from_str("Deny"));
        deny.setKeyEquivalent(&NSString::from_str("\u{1b}"));
        let mut allows: Vec<Retained<NSButton>> = Vec::new();
        for (i, c) in p.choices.iter().enumerate() {
            let b = alert.addButtonWithTitle(&NSString::from_str(&c.label));
            let key = if p.default_choice == Some(i) {
                "\r"
            } else {
                ""
            };
            b.setKeyEquivalent(&NSString::from_str(key));
            b.setEnabled(false);
            allows.push(b);
        }
        alert.layout();
        let window = alert.window();
        window.setLevel(NSFloatingWindowLevel);
        window.setCollectionBehavior(
            NSWindowCollectionBehavior::CanJoinAllSpaces
                | NSWindowCollectionBehavior::FullScreenAuxiliary,
        );
        if let Some(f) = &field {
            let fv: &NSView = f;
            window.setInitialFirstResponder(Some(fv));
        }
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        // Arming delay and countdown, fired inside the modal loop.
        let armed = Rc::new(Cell::new(false));
        let timer_app = app.clone();
        let timer_label = countdown.clone();
        let timer_buttons = allows.clone();
        let armed_in = armed.clone();
        let block = RcBlock::new(move |_t: NonNull<NSTimer>| {
            if !armed_in.get() && started.elapsed() >= ARM_DELAY {
                armed_in.set(true);
                for b in &timer_buttons {
                    b.setEnabled(true);
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            timer_label.setStringValue(&NSString::from_str(&clock(left)));
            if left.is_zero() {
                timer_app.abortModal();
            }
        });
        // SAFETY: the block only touches main-thread objects, on the main thread.
        let timer = unsafe { NSTimer::timerWithTimeInterval_repeats_block(0.25, true, &block) };
        // SAFETY: common modes include the modal panel mode.
        unsafe { NSRunLoop::currentRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes) };

        let response = alert.runModal();
        timer.invalidate();

        if response == NSModalResponseAbort {
            return Pass::Done(Decision::TimedOut);
        }
        let k = response - NSAlertFirstButtonReturn - 1;
        if response == NSAlertFirstButtonReturn || k < 0 || k as usize >= p.choices.len() {
            return Pass::Done(Decision::Denied);
        }
        let k = k as usize;
        let value = field.as_ref().map(|f| f.stringValue().to_string());
        if value.as_deref().is_some_and(|v| v.trim().is_empty()) {
            return Pass::Again("Enter a value first.".to_string());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        match touchid::confirm_blocking(&p.touch_reason, left) {
            Outcome::Approved => Pass::Done(Decision::Approved { choice: k, value }),
            Outcome::Denied => {
                Pass::Again("Touch ID was cancelled. Choose again or Deny.".to_string())
            }
            Outcome::TimedOut => Pass::Done(Decision::TimedOut),
            Outcome::Unavailable => Pass::Done(Decision::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_round_trips() {
        let p = Prompt {
            title: "Share a password".into(),
            rows: vec![Row {
                label: "Item".into(),
                value: "GitHub".into(),
            }],
            note: Some("n".into()),
            choices: vec![Choice {
                label: "Allow once".into(),
                minutes: None,
            }],
            default_choice: Some(0),
            touch_reason: "share GitHub".into(),
            timeout_secs: 60,
            input: None,
        };
        let json = serde_json::to_string(&p).expect("ser");
        assert_eq!(serde_json::from_str::<Prompt>(&json).expect("de"), p);
    }

    #[test]
    fn decisions_parse() {
        let d: Decision = serde_json::from_str(r#"{"decision":"approved","choice":1}"#).expect("a");
        assert!(matches!(
            d,
            Decision::Approved {
                choice: 1,
                value: None
            }
        ));
        for (s, ok) in [
            (r#"{"decision":"denied"}"#, true),
            (r#"{"decision":"timed_out"}"#, true),
            (r#"{"decision":"unavailable"}"#, true),
            (r#"{"decision":"maybe"}"#, false),
        ] {
            assert_eq!(serde_json::from_str::<Decision>(s).is_ok(), ok, "{s}");
        }
    }
}

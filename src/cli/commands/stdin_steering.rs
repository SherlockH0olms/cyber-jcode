//! Opt-in text steering for Cyber-Jcode's headless console.
use crate::agent::{SoftInterruptMessage, SoftInterruptQueue, SoftInterruptSource};
use serde_json::Value;
use std::io::BufRead;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

pub(super) struct StdinSteering {
    active: Arc<AtomicBool>,
    queue: SoftInterruptQueue,
    pub notices: UnboundedReceiver<Value>,
}

fn parse_instruction(line: &str) -> Option<(String, String)> {
    if line.len() > 64 * 1024 {
        return None;
    }
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("type")?.as_str()? != "steer" {
        return None;
    }
    let id = value.get("id")?.as_str()?;
    let text = value.get("text")?.as_str()?.trim();
    if !id.starts_with("cyber-stdin-")
        || id.len() > 100
        || text.is_empty()
        || text.len() > 32 * 1024
    {
        return None;
    }
    Some((id.to_string(), text.to_string()))
}

impl StdinSteering {
    pub fn start(queue: SoftInterruptQueue) -> Self {
        let active = Arc::new(AtomicBool::new(true));
        let (sender, notices) = unbounded_channel();
        let input_active = active.clone();
        let input_queue = queue.clone();
        // A std thread does not keep Tokio's blocking pool alive after the run.
        // The parent closes this pipe at task end. No stdin reader is installed
        // for normal upstream Jcode invocations.
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                let Some((id, content)) = parse_instruction(&line) else {
                    continue;
                };
                let Ok(mut queue) = input_queue.lock() else {
                    break;
                };
                if !input_active.load(Ordering::SeqCst) {
                    break;
                }
                queue.push(SoftInterruptMessage {
                    content,
                    images: Vec::new(),
                    urgent: false,
                    source: SoftInterruptSource::User,
                    client_id: Some(id.clone()),
                });
                drop(queue);
                let _ = sender.send(serde_json::json!({"type":"steering_queued", "id":id}));
            }
        });
        Self {
            active,
            queue,
            notices,
        }
    }

    pub fn stop_and_take_pending(&self) -> Vec<String> {
        self.active.store(false, Ordering::SeqCst);
        let mut ids = Vec::new();
        if let Ok(mut queue) = self.queue.lock() {
            queue.retain(|message| {
                if let Some(id) = &message.client_id {
                    if id.starts_with("cyber-stdin-") {
                        ids.push(id.clone());
                        return false;
                    }
                }
                true
            });
        }
        ids
    }
}

impl Drop for StdinSteering {
    fn drop(&mut self) {
        let _ = self.stop_and_take_pending();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_bounded_text_instructions() {
        assert_eq!(
            parse_instruction(
                r#"{"type":"steer","id":"cyber-stdin-1","text":"Continue with the new clue"}"#
            ),
            Some(("cyber-stdin-1".into(), "Continue with the new clue".into()))
        );
        assert!(parse_instruction(r#"{"type":"image","data":"private"}"#).is_none());
        assert!(parse_instruction(r#"{"type":"steer","id":"foreign","text":"hello"}"#).is_none());
    }
}

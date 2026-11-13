//! Per-client display override used by Cyber-Jcode's Skull mode.
//! This never changes provider reasoning, saved config, or session evidence.

use std::borrow::Cow;

pub(super) fn hidden() -> bool {
    std::env::var("JCODE_TUI_HIDE_THINKING").as_deref() == Ok("1")
}

pub(super) fn visible() -> bool {
    !hidden() && crate::config::config().display.reasoning_enabled()
}

pub(super) fn assistant_text(content: &str) -> Cow<'_, str> {
    project_assistant_text(content, hidden())
}

fn project_assistant_text(content: &str, hide: bool) -> Cow<'_, str> {
    if !hide || !content.contains(jcode_tui_markdown::REASONING_SENTINEL) {
        return Cow::Borrowed(content);
    }
    // Only Jcode's explicitly marked reasoning lines are removed. Ordinary
    // italic prose, answers, commands and tool output retain their content.
    Cow::Owned(
        content
            .lines()
            .filter(|line| !line.contains(jcode_tui_markdown::REASONING_SENTINEL))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skull_hides_retained_reasoning_and_keeps_normal_answers() {
        let text = "*\u{2063}PRIVATE_REASONING*\n\n**Answer:** Hello.\n*Ordinary emphasis.*";
        assert_eq!(
            project_assistant_text(text, true),
            "**Answer:** Hello.\n*Ordinary emphasis.*"
        );
        assert!(
            text.contains("PRIVATE_REASONING"),
            "source evidence is untouched"
        );
    }

    #[test]
    fn normal_display_and_unmarked_content_are_unchanged() {
        let text = "*\u{2063}PRIVATE_REASONING*\n\nAnswer.";
        assert_eq!(project_assistant_text(text, false), text);
        assert_eq!(project_assistant_text("*Hello.*", true), "*Hello.*");
    }
}

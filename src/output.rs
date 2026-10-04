//! CLI output formatting.

use crate::ProbeResult;

/// Output format selected by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Emit every probe result as one JSON object per line.
    JsonLines,
    /// Emit only the final URL of successful probes, one per line.
    Urls,
}

/// Render one probe result, or return `None` when the selected format omits it.
pub fn render_result(
    result: &ProbeResult,
    format: OutputFormat,
) -> serde_json::Result<Option<String>> {
    match format {
        OutputFormat::JsonLines => serde_json::to_string(result).map(Some),
        OutputFormat::Urls => Ok(if result.ok {
            result.url.clone()
        } else {
            None
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn successful_result() -> ProbeResult {
        let mut result = ProbeResult::failed("example.com", "example.com", "unused");
        result.ok = true;
        result.url = Some("https://example.com/final".to_string());
        result.error = None;
        result
    }

    #[test]
    fn json_lines_include_successful_results() {
        let rendered = render_result(&successful_result(), OutputFormat::JsonLines)
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(value["ok"], true);
        assert_eq!(value["url"], "https://example.com/final");
    }

    #[test]
    fn json_lines_include_failed_results() {
        let failed = ProbeResult::failed("offline.example", "offline.example", "timed out");
        let rendered = render_result(&failed, OutputFormat::JsonLines)
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "timed out");
    }

    #[test]
    fn urls_emit_only_the_final_url_for_successes() {
        assert_eq!(
            render_result(&successful_result(), OutputFormat::Urls).unwrap(),
            Some("https://example.com/final".to_string())
        );
    }

    #[test]
    fn urls_omit_failed_results_even_if_a_url_is_present() {
        let mut failed = ProbeResult::failed("offline.example", "offline.example", "timed out");
        failed.url = Some("https://offline.example/".to_string());

        assert_eq!(render_result(&failed, OutputFormat::Urls).unwrap(), None);
    }
}

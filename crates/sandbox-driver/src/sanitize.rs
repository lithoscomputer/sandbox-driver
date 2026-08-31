use serde::{Deserialize, Serialize};

/// Policy for command output returned by [`crate::Exec::run`] and
/// [`crate::Exec::run_streaming`].
///
/// Non-raw policies are lossy and are intended for textual output. Use
/// [`OutputSanitization::Raw`] when output can contain arbitrary binary data.
/// PTY sessions and long-lived bidirectional stdio processes always remain
/// raw.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputSanitization {
    /// Return output bytes without modification.
    #[default]
    Raw,
    /// Remove ANSI terminal escape sequences. Preserve standalone control
    /// characters.
    StripAnsi,
    /// Remove ANSI terminal escape sequences and standalone C0/C1 control
    /// characters, except tab, line feed, and carriage return.
    StripAll,
}

impl OutputSanitization {
    /// Applies this policy to a complete output buffer.
    #[must_use]
    pub fn sanitize(self, bytes: &[u8]) -> Vec<u8> {
        let mut sanitizer = OutputSanitizer::new(self);
        let mut output = sanitizer.push(bytes);
        output.extend(sanitizer.finish());
        output
    }
}

/// Stateful output sanitizer for output that arrives in chunks.
///
/// One instance must be used for each independent output stream. This keeps
/// an escape sequence private even when the sequence spans multiple chunks.
#[derive(Debug)]
pub struct OutputSanitizer {
    policy:         OutputSanitization,
    state:          State,
    pending_c2:     bool,
    utf8_remaining: u8,
}

impl OutputSanitizer {
    #[must_use]
    pub fn new(policy: OutputSanitization) -> Self {
        Self {
            policy,
            state: State::Ground,
            pending_c2: false,
            utf8_remaining: 0,
        }
    }

    /// Sanitizes the next chunk and returns bytes that are ready for the
    /// caller. The returned buffer can be empty.
    #[must_use]
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.policy == OutputSanitization::Raw {
            return chunk.to_vec();
        }

        let mut output = Vec::with_capacity(chunk.len());
        for &byte in chunk {
            self.process(byte, &mut output);
        }
        output
    }

    /// Finishes the stream.
    ///
    /// An incomplete escape sequence is removed. A pending byte that is not
    /// part of an escape sequence is preserved.
    #[must_use]
    pub fn finish(&mut self) -> Vec<u8> {
        if self.policy == OutputSanitization::Raw {
            return Vec::new();
        }

        let mut output = Vec::new();
        if self.state == State::Ground && self.pending_c2 {
            output.push(0xc2);
        }
        self.state = State::Ground;
        self.pending_c2 = false;
        self.utf8_remaining = 0;
        output
    }

    fn process(&mut self, byte: u8, output: &mut Vec<u8>) {
        match self.state {
            State::Ground => self.process_ground(byte, output),
            State::Escape => self.process_escape(byte, output),
            State::EscapeIntermediate => self.process_escape_intermediate(byte),
            State::Csi => self.process_csi(byte),
            State::Osc => self.process_osc(byte),
            State::OscEscape => self.process_osc_escape(byte),
            State::OscC2 => self.process_osc_c2(byte),
            State::ControlString => self.process_control_string(byte),
            State::ControlStringEscape => self.process_control_string_escape(byte),
            State::ControlStringC2 => self.process_control_string_c2(byte),
        }
    }

    fn process_ground(&mut self, byte: u8, output: &mut Vec<u8>) {
        if self.pending_c2 {
            self.pending_c2 = false;
            match byte {
                0x80..=0x9f => {
                    self.process_c1(byte, output, true);
                    return;
                }
                0xa0..=0xbf => {
                    output.extend_from_slice(&[0xc2, byte]);
                    return;
                }
                _ => output.push(0xc2),
            }
        }

        if self.utf8_remaining > 0 {
            if (0x80..=0xbf).contains(&byte) {
                output.push(byte);
                self.utf8_remaining -= 1;
                return;
            }
            self.utf8_remaining = 0;
        }

        match byte {
            0x1b => self.state = State::Escape,
            0x80..=0x9f => self.process_c1(byte, output, false),
            0xc2 => self.pending_c2 = true,
            0xc3..=0xdf => {
                output.push(byte);
                self.utf8_remaining = 1;
            }
            0xe0..=0xef => {
                output.push(byte);
                self.utf8_remaining = 2;
            }
            0xf0..=0xf4 => {
                output.push(byte);
                self.utf8_remaining = 3;
            }
            0x00..=0x1f | 0x7f if self.policy == OutputSanitization::StripAll => {
                if matches!(byte, b'\t' | b'\n' | b'\r') {
                    output.push(byte);
                }
            }
            _ => output.push(byte),
        }
    }

    fn process_c1(&mut self, byte: u8, output: &mut Vec<u8>, utf8_encoded: bool) {
        match byte {
            0x90 | 0x98 | 0x9e | 0x9f => self.state = State::ControlString,
            0x9b => self.state = State::Csi,
            0x9d => self.state = State::Osc,
            0x9c => {}
            _ if self.policy == OutputSanitization::StripAnsi => {
                if utf8_encoded {
                    output.push(0xc2);
                }
                output.push(byte);
            }
            _ => {}
        }
    }

    fn process_escape(&mut self, byte: u8, output: &mut Vec<u8>) {
        match byte {
            b'[' => self.state = State::Csi,
            b']' => self.state = State::Osc,
            b'P' | b'X' | b'^' | b'_' => self.state = State::ControlString,
            0x20..=0x2f => self.state = State::EscapeIntermediate,
            0x30..=0x7e => self.state = State::Ground,
            0x1b => {}
            _ => {
                self.state = State::Ground;
                self.process_ground(byte, output);
            }
        }
    }

    fn process_escape_intermediate(&mut self, byte: u8) {
        match byte {
            0x30..=0x7e => self.state = State::Ground,
            0x1b => self.state = State::Escape,
            _ => {}
        }
    }

    fn process_csi(&mut self, byte: u8) {
        match byte {
            0x40..=0x7e => self.state = State::Ground,
            0x1b => self.state = State::Escape,
            _ => {}
        }
    }

    fn process_osc(&mut self, byte: u8) {
        match byte {
            0x07 | 0x9c => self.state = State::Ground,
            0x1b => self.state = State::OscEscape,
            0xc2 => self.state = State::OscC2,
            _ => {}
        }
    }

    fn process_osc_escape(&mut self, byte: u8) {
        match byte {
            b'\\' => self.state = State::Ground,
            0x1b => {}
            0xc2 => self.state = State::OscC2,
            _ => self.state = State::Osc,
        }
    }

    fn process_osc_c2(&mut self, byte: u8) {
        match byte {
            0x07 | 0x9c => self.state = State::Ground,
            0x1b => self.state = State::OscEscape,
            0xc2 => {}
            _ => self.state = State::Osc,
        }
    }

    fn process_control_string(&mut self, byte: u8) {
        match byte {
            0x9c => self.state = State::Ground,
            0x1b => self.state = State::ControlStringEscape,
            0xc2 => self.state = State::ControlStringC2,
            _ => {}
        }
    }

    fn process_control_string_escape(&mut self, byte: u8) {
        match byte {
            b'\\' => self.state = State::Ground,
            0x1b => {}
            0xc2 => self.state = State::ControlStringC2,
            _ => self.state = State::ControlString,
        }
    }

    fn process_control_string_c2(&mut self, byte: u8) {
        match byte {
            0x9c => self.state = State::Ground,
            0x1b => self.state = State::ControlStringEscape,
            0xc2 => {}
            _ => self.state = State::ControlString,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Ground,
    Escape,
    EscapeIntermediate,
    Csi,
    Osc,
    OscEscape,
    OscC2,
    ControlString,
    ControlStringEscape,
    ControlStringC2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_preserves_arbitrary_bytes() {
        let bytes = b"\x00\x1b[31mred\x1b[0m\xff";
        assert_eq!(OutputSanitization::Raw.sanitize(bytes), bytes);
    }

    #[test]
    fn strip_ansi_preserves_standalone_controls() {
        let bytes = b"\x1b[31mred\x1b[0m\x07\x01\n";
        assert_eq!(
            OutputSanitization::StripAnsi.sanitize(bytes),
            b"red\x07\x01\n"
        );
    }

    #[test]
    fn strip_all_preserves_common_text_controls() {
        let bytes = b"\x1b[31mred\x1b[0m\x07\x01\x08\x7f\t\r\n";
        assert_eq!(OutputSanitization::StripAll.sanitize(bytes), b"red\t\r\n");
    }

    #[test]
    fn sequences_can_span_chunks() {
        let mut sanitizer = OutputSanitizer::new(OutputSanitization::StripAnsi);
        let mut output = sanitizer.push(b"before\x1b]");
        output.extend(sanitizer.push(b"0;secret"));
        output.extend(sanitizer.push(b"\x1b\\after\x1bPprivate"));
        output.extend(sanitizer.push(b"\xc2\x9cend"));
        output.extend(sanitizer.finish());
        assert_eq!(output, b"beforeafterend");
    }

    #[test]
    fn preserves_utf8_with_c1_range_continuation_bytes() {
        let bytes = "Arabic semicolon: ؛".as_bytes();
        assert_eq!(OutputSanitization::StripAll.sanitize(bytes), bytes);
    }

    #[test]
    fn recognizes_utf8_encoded_c1_sequences() {
        let bytes = b"before\xc2\x9b31mred\xc2\x9b0mafter";
        assert_eq!(
            OutputSanitization::StripAnsi.sanitize(bytes),
            b"beforeredafter"
        );
    }

    #[test]
    fn finish_preserves_non_escape_pending_byte() {
        let mut sanitizer = OutputSanitizer::new(OutputSanitization::StripAnsi);
        assert_eq!(sanitizer.push(b"text\xc2"), b"text");
        assert_eq!(sanitizer.finish(), b"\xc2");

        let mut sanitizer = OutputSanitizer::new(OutputSanitization::StripAnsi);
        assert_eq!(sanitizer.push(b"text\x1b]unfinished"), b"text");
        assert!(sanitizer.finish().is_empty());
    }

    #[test]
    fn streaming_matches_one_shot() {
        let bytes = b"a\x1b[31mred\x1b[0m\x01\n";
        let expected = OutputSanitization::StripAll.sanitize(bytes);
        let mut sanitizer = OutputSanitizer::new(OutputSanitization::StripAll);
        let mut actual = Vec::new();
        for chunk in bytes.chunks(2) {
            actual.extend(sanitizer.push(chunk));
        }
        actual.extend(sanitizer.finish());
        assert_eq!(actual, expected);
    }
}

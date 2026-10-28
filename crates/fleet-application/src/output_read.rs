//! Bounded reads of persisted Job output. Cursors identify an untrusted read
//! position, never execution authority, capture completeness, or receipt state.
//! Adapters own snapshot consistency, byte-bounded I/O and retention invalidation.

use crate::JobOutputStream;
use fleet_domain::{AgentId, JobId, JobStatus};
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputReadScope {
    pub job_id: JobId,
    pub agent_id: Option<AgentId>,
    pub stream: Option<JobOutputStream>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputReadLimits {
    fragments: usize,
    source_bytes: usize,
}

impl OutputReadLimits {
    pub fn new(fragments: usize, source_bytes: usize) -> Result<Self, OutputReadError> {
        if !(1..=256).contains(&fragments) || !(4096..=262_144).contains(&source_bytes) {
            return Err(OutputReadError::InvalidLimit);
        }
        Ok(Self {
            fragments,
            source_bytes,
        })
    }

    pub fn fragments(self) -> usize {
        self.fragments
    }
    pub fn source_bytes(self) -> usize {
        self.source_bytes
    }
}

impl Default for OutputReadLimits {
    fn default() -> Self {
        Self {
            fragments: 128,
            source_bytes: 65_536,
        }
    }
}

/// Store identity is a purpose-separated digest of namespace and restore epoch.
/// Retention generation and position are scoped to one Job/filter combination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputReadCursor {
    scope: OutputReadScope,
    store_stamp: [u8; 32],
    generation: i64,
    row: i64,
    offset: i64,
    fence: Option<i64>,
}

impl OutputReadCursor {
    /// Validates structural bounds only; the adapter checks persisted scope,
    /// epoch, generation, row ownership and UTF-8 byte position on every read.
    pub fn new(
        scope: OutputReadScope,
        store_stamp: [u8; 32],
        generation: i64,
        row: i64,
        offset: i64,
        fence: Option<i64>,
    ) -> Result<Self, OutputReadError> {
        if generation < 0
            || row < 0
            || offset < 0
            || (row == 0 && offset != 0)
            || fence.is_some_and(|f| f < row)
        {
            return Err(OutputReadError::InvalidCursor);
        }
        Ok(Self {
            scope,
            store_stamp,
            generation,
            row,
            offset,
            fence,
        })
    }
    pub fn scope(&self) -> &OutputReadScope {
        &self.scope
    }
    pub fn store_stamp(&self) -> &[u8; 32] {
        &self.store_stamp
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
    pub fn row(&self) -> i64 {
        self.row
    }
    pub fn offset(&self) -> i64 {
        self.offset
    }
    pub fn fence(&self) -> Option<i64> {
        self.fence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputHistory {
    Tracked,
    Unknown,
    Pruned,
}

/// Byte positions and row/sequence identifiers retain the SQLite i64 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFragmentPosition {
    pub chunk_key: i64,
    pub sequence: i64,
    pub offset_bytes: i64,
    pub total_bytes: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OutputFragment {
    position: OutputFragmentPosition,
    agent_id: AgentId,
    stream: JobOutputStream,
    data: String,
}

impl OutputFragment {
    pub fn new(
        position: OutputFragmentPosition,
        agent_id: AgentId,
        stream: JobOutputStream,
        data: String,
    ) -> Result<Self, OutputReadError> {
        let size = i64::try_from(data.len()).map_err(|_| OutputReadError::Unavailable)?;
        if position.chunk_key <= 0
            || position.sequence < 0
            || position.offset_bytes < 0
            || position.total_bytes < position.offset_bytes
            || size > position.total_bytes - position.offset_bytes
            || (size == 0 && position.total_bytes != 0)
        {
            return Err(OutputReadError::Unavailable);
        }
        Ok(Self {
            position,
            agent_id,
            stream,
            data,
        })
    }
    pub fn position(&self) -> OutputFragmentPosition {
        self.position
    }
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }
    pub fn stream(&self) -> JobOutputStream {
        self.stream
    }
    pub fn data(&self) -> &str {
        &self.data
    }
    pub fn chunk_complete(&self) -> bool {
        self.position.offset_bytes + self.data.len() as i64 == self.position.total_bytes
    }
    /// Budget counts repeated Agent/stream metadata, plus unescaped UTF-8 data.
    pub fn source_bytes(&self) -> usize {
        self.agent_id.as_str().len() + 6 + self.data.len()
    }
}

impl Debug for OutputFragment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputFragment")
            .field("position", &self.position)
            .field("stream", &self.stream)
            .field("data_bytes", &self.data.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPage {
    pub items: Vec<OutputFragment>,
    pub next: OutputReadCursor,
    pub has_more: bool,
    pub caught_up: bool,
    pub history: OutputHistory,
    pub job_status: JobStatus,
}

/// Public read failures deliberately omit SQL, raw output and opaque cursor text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputReadError {
    InvalidLimit,
    ScopeMismatch,
    InvalidCursor,
    StaleCursor,
    JobNotFound,
    MetadataTooLarge,
    Unavailable,
}

impl Display for OutputReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "invalid output page limit",
            Self::ScopeMismatch => "output cursor scope mismatch",
            Self::InvalidCursor => "invalid output cursor position",
            Self::StaleCursor => "output cursor is stale",
            Self::JobNotFound => "output job not found",
            Self::MetadataTooLarge => "output metadata exceeds page budget",
            Self::Unavailable => "output read state unavailable",
        })
    }
}
impl std::error::Error for OutputReadError {}

/// Reads one consistent canonical status/projection/output snapshot. Implementors
/// must enforce scope and stale-position checks even when called without a use case.
/// A full-body query followed by in-memory slicing violates this port's contract.
pub trait OutputPageRepository {
    fn read_output_page(
        &self,
        scope: &OutputReadScope,
        after: Option<&OutputReadCursor>,
        limits: OutputReadLimits,
    ) -> Result<OutputPage, OutputReadError>;
}

pub struct ReadJobOutputPage;
impl ReadJobOutputPage {
    /// Does not authenticate: the interface must enforce Job-read permission first.
    pub fn execute<R: OutputPageRepository>(
        repo: &R,
        scope: &OutputReadScope,
        after: Option<&OutputReadCursor>,
        limits: OutputReadLimits,
    ) -> Result<OutputPage, OutputReadError> {
        if after.is_some_and(|cursor| cursor.scope() != scope) {
            return Err(OutputReadError::ScopeMismatch);
        }
        repo.read_output_page(scope, after, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn scope(job: &str) -> OutputReadScope {
        OutputReadScope {
            job_id: JobId::new(job).unwrap(),
            agent_id: None,
            stream: None,
        }
    }

    #[test]
    fn output_page_limits_reject_out_of_bounds_instead_of_clamping() {
        for (n, bytes) in [
            (0, 4096),
            (257, 4096),
            (1, 4095),
            (1, 262145),
            (usize::MAX, usize::MAX),
        ] {
            assert_eq!(
                OutputReadLimits::new(n, bytes),
                Err(OutputReadError::InvalidLimit)
            );
        }
        for (n, bytes) in [(1, 4096), (256, 262144), (128, 65536)] {
            let limits = OutputReadLimits::new(n, bytes).unwrap();
            assert_eq!((limits.fragments(), limits.source_bytes()), (n, bytes));
        }
        assert_eq!(
            OutputReadLimits::default(),
            OutputReadLimits::new(128, 65536).unwrap()
        );
    }

    #[test]
    fn output_cursor_rejects_impossible_structure_and_preserves_large_integers() {
        for (g, r, o, f) in [
            (-1, 0, 0, None),
            (0, -1, 0, None),
            (0, 0, -1, None),
            (0, 0, 1, None),
            (0, 1, 0, Some(0)),
            (0, 0, 0, Some(-1)),
        ] {
            assert_eq!(
                OutputReadCursor::new(scope("a"), [0; 32], g, r, o, f),
                Err(OutputReadError::InvalidCursor)
            );
        }
        let c = OutputReadCursor::new(
            scope("a"),
            [7; 32],
            i64::MAX,
            i64::MAX,
            i64::MAX,
            Some(i64::MAX),
        )
        .unwrap();
        assert_eq!(
            (c.generation(), c.row(), c.offset(), c.fence()),
            (i64::MAX, i64::MAX, i64::MAX, Some(i64::MAX))
        );
    }

    #[test]
    fn output_fragment_rejects_nonprogress_and_overflow_but_accepts_empty_row() {
        let agent = AgentId::new("a").unwrap();
        for p in [
            OutputFragmentPosition {
                chunk_key: 0,
                sequence: 0,
                offset_bytes: 0,
                total_bytes: 0,
            },
            OutputFragmentPosition {
                chunk_key: 1,
                sequence: -1,
                offset_bytes: 0,
                total_bytes: 0,
            },
            OutputFragmentPosition {
                chunk_key: 1,
                sequence: 0,
                offset_bytes: -1,
                total_bytes: 0,
            },
            OutputFragmentPosition {
                chunk_key: 1,
                sequence: 0,
                offset_bytes: 0,
                total_bytes: 1,
            },
            OutputFragmentPosition {
                chunk_key: 1,
                sequence: 0,
                offset_bytes: 1,
                total_bytes: 0,
            },
        ] {
            assert_eq!(
                OutputFragment::new(p, agent.clone(), JobOutputStream::Stdout, String::new()),
                Err(OutputReadError::Unavailable)
            );
        }
        let empty = OutputFragment::new(
            OutputFragmentPosition {
                chunk_key: 1,
                sequence: 0,
                offset_bytes: 0,
                total_bytes: 0,
            },
            agent.clone(),
            JobOutputStream::Stderr,
            String::new(),
        )
        .unwrap();
        assert!(empty.chunk_complete());
        let p = OutputFragmentPosition {
            chunk_key: i64::MAX,
            sequence: i64::MAX,
            offset_bytes: i64::MAX - 1,
            total_bytes: i64::MAX,
        };
        assert!(
            OutputFragment::new(p, agent.clone(), JobOutputStream::Stdout, "x".into())
                .unwrap()
                .chunk_complete()
        );
        assert_eq!(
            OutputFragment::new(p, agent, JobOutputStream::Stdout, "xx".into()),
            Err(OutputReadError::Unavailable)
        );
    }

    #[test]
    fn output_scope_is_checked_before_any_repository_read() {
        struct Probe(Cell<usize>);
        impl OutputPageRepository for Probe {
            fn read_output_page(
                &self,
                _: &OutputReadScope,
                _: Option<&OutputReadCursor>,
                _: OutputReadLimits,
            ) -> Result<OutputPage, OutputReadError> {
                self.0.set(self.0.get() + 1);
                Err(OutputReadError::Unavailable)
            }
        }
        let repo = Probe(Cell::new(0));
        let a = scope("a");
        let mut changes = vec![scope("b")];
        let mut agent = a.clone();
        agent.agent_id = Some(AgentId::new("agent").unwrap());
        changes.push(agent);
        let mut stream = a.clone();
        stream.stream = Some(JobOutputStream::Stderr);
        changes.push(stream);
        for other in changes {
            let cursor = OutputReadCursor::new(other, [1; 32], 0, 0, 0, None).unwrap();
            assert_eq!(
                ReadJobOutputPage::execute(&repo, &a, Some(&cursor), OutputReadLimits::default()),
                Err(OutputReadError::ScopeMismatch)
            );
        }
        assert_eq!(repo.0.get(), 0);
        assert_eq!(
            ReadJobOutputPage::execute(&repo, &a, None, OutputReadLimits::default()),
            Err(OutputReadError::Unavailable)
        );
        assert_eq!(repo.0.get(), 1);
    }

    #[test]
    fn output_fragment_debug_redacts_payload_and_agent_metadata() {
        let text = "private-command-output";
        let fragment = OutputFragment::new(
            OutputFragmentPosition {
                chunk_key: 1,
                sequence: 0,
                offset_bytes: 0,
                total_bytes: text.len() as i64,
            },
            AgentId::new("private-agent-name").unwrap(),
            JobOutputStream::Stdout,
            text.into(),
        )
        .unwrap();
        let debug = format!("{fragment:?}");
        assert!(!debug.contains(text));
        assert!(!debug.contains("private-agent-name"));
        assert_eq!(fragment.source_bytes(), 18 + 6 + text.len());
    }
}

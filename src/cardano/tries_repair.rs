//! Shared startup and runtime repair of the two cumulative bridge tries.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;

use crate::cardano::bridge_state::TriesStatus;
use crate::cardano::cpo_history::CpoHistorySource;
use crate::cardano::cpo_trie::{self, ReconstructConfig};
use crate::epoch::pending_tm::PendingTm;

pub const TRIES_REPAIR_BUDGET: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
pub enum RepairError {
    HeadMoved {
        walked: bitcoin::OutPoint,
        expected: bitcoin::OutPoint,
    },
    Failed(String),
}

impl std::fmt::Display for RepairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeadMoved { walked, expected } => write!(
                f,
                "the history walk read treasury head {walked}, but the caller will spend {expected}"
            ),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for RepairError {}

/// What a repair installed.
///
/// The event line is the CALLER's to write, not the repairer's: the runtime
/// caller knows the node and the epoch, and writes it under the same
/// `[epoch=…]` prefix as every other event of that node; the startup caller
/// has neither yet. [`Self::describe`] keeps the two wordings one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repaired {
    /// The rebuilt roots — already held against the singleton by
    /// `reconstruct_both`, which refuses a pair the singleton does not attest.
    pub cpo_root: [u8; 32],
    pub spi_root: [u8; 32],
    /// Why `pending-tm.json` is still there when the repair meant to remove it.
    /// Not a failure of the repair — see [`drop_pending_record`].
    pub pending_kept: Option<String>,
}

impl Repaired {
    /// The event text: the outcome first, then what the tries were before.
    ///
    /// `before` is labelled because it is the state the rebuild REPLACED: after
    /// "tries rebuilt", a bare "spi root X != the chain's Y" reads as the
    /// rebuild's outcome.
    #[must_use]
    pub fn describe(&self, head: bitcoin::OutPoint, before: &str) -> String {
        let mut out = format!(
            "tries rebuilt from chain history at treasury head {head}; they now match the \
             bridge-state singleton (cpo root {}, spi root {}). Before the rebuild: {before}",
            hex::encode(self.cpo_root),
            hex::encode(self.spi_root)
        );
        if let Some(e) = &self.pending_kept {
            out.push_str(&format!(
                ". The pending-movement record could not be removed ({e}) and stays; a fold \
                 must still reproduce the roots its movement committed, so it cannot move \
                 these tries anywhere the chain has not"
            ));
        }
        out
    }
}

#[async_trait]
pub trait TriesRepairer: Send + Sync + std::fmt::Debug {
    async fn repair(
        &self,
        state_dir: &Path,
        status: &TriesStatus,
        head: bitcoin::OutPoint,
    ) -> Result<Repaired, RepairError>;
}

pub struct ChainTriesRepairer {
    source: Box<dyn CpoHistorySource>,
    recon: ReconstructConfig,
    budget: Duration,
}

impl std::fmt::Debug for ChainTriesRepairer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainTriesRepairer")
            .field("backend", &self.source.backend())
            .field("endpoint", &self.source.endpoint())
            .field("recon", &self.recon)
            .field("budget", &self.budget)
            .finish()
    }
}

impl ChainTriesRepairer {
    #[must_use]
    pub fn new(source: Box<dyn CpoHistorySource>, recon: ReconstructConfig) -> Self {
        Self {
            source,
            recon,
            budget: TRIES_REPAIR_BUDGET,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }
}

fn keep_copies(state_dir: &Path) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    for name in ["cpo-trie.json", "spi-trie.json"] {
        let from = state_dir.join(name);
        if !from.exists() {
            continue;
        }
        let to = state_dir.join(format!("{name}.superseded-{stamp}"));
        match std::fs::copy(&from, &to) {
            Ok(_) => tracing::warn!("kept superseded trie as {}", to.display()),
            Err(e) => tracing::warn!("could not copy {} aside: {e}", from.display()),
        }
    }
}

fn install_pair(
    state_dir: &Path,
    cpo: &cpo_trie::CpoTrie,
    spi: &crate::cardano::spi_trie::SpiTrie,
) -> Result<(), String> {
    let stage = state_dir.join(format!(".tries-repair-{}", std::process::id()));
    std::fs::create_dir_all(&stage).map_err(|e| format!("create {}: {e}", stage.display()))?;
    cpo.save(&stage).map_err(|e| e.to_string())?;
    spi.save(&stage).map_err(|e| e.to_string())?;

    // Both replays have succeeded before either live file changes. Keep rollback
    // copies during the two renames so an I/O failure cannot leave a mixed pair.
    let names = ["cpo-trie.json", "spi-trie.json"];
    let mut old: Vec<(PathBuf, PathBuf)> = Vec::new();
    for name in names {
        let live = state_dir.join(name);
        let backup = stage.join(format!("old-{name}"));
        if live.exists() {
            if let Err(e) = std::fs::rename(&live, &backup) {
                for (saved, original) in old {
                    let _ = std::fs::rename(saved, original);
                }
                let _ = std::fs::remove_dir_all(&stage);
                return Err(format!("stage {}: {e}", live.display()));
            }
            old.push((backup, live));
        }
    }
    let install = (|| {
        for name in names {
            std::fs::rename(stage.join(name), state_dir.join(name))
                .map_err(|e| format!("install {name}: {e}"))?;
        }
        Ok::<_, String>(())
    })();
    if let Err(e) = install {
        for name in names {
            let _ = std::fs::remove_file(state_dir.join(name));
        }
        for (backup, live) in old {
            let _ = std::fs::rename(backup, live);
        }
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }
    let _ = std::fs::remove_dir_all(&stage);
    Ok(())
}

/// Remove the pending-movement record once the rebuilt pair is installed —
/// returning why it could not be, never failing on it.
///
/// By now the rebuilt tries are on disk and match the singleton, so raising
/// here would report a rebuild that SUCCEEDED as failed: the startup event
/// would say FAILED over tries that step 10 then passes, and a runtime batch
/// would stop on `TriesBehind` with its tries in sync. A record left behind is
/// harmless: a fold writes nothing unless it reproduces the two roots its
/// movement committed, so the record either folds correctly or is refused and
/// set aside.
///
/// The unlink needs only the directory write access `install_pair` has just
/// used, so this fails only on a state directory already in trouble: the file
/// made immutable, a directory where the file should be, or the filesystem
/// remounted read-only after an I/O error in between.
fn drop_pending_record(state_dir: &Path) -> Option<String> {
    PendingTm::clear(state_dir).err()
}

#[async_trait]
impl TriesRepairer for ChainTriesRepairer {
    async fn repair(
        &self,
        state_dir: &Path,
        status: &TriesStatus,
        head: bitcoin::OutPoint,
    ) -> Result<Repaired, RepairError> {
        if matches!(
            status,
            TriesStatus::Diverged { .. } | TriesStatus::Unreadable { .. }
        ) {
            keep_copies(state_dir);
        }
        let rebuilt = tokio::time::timeout(
            self.budget,
            cpo_trie::reconstruct_both(self.source.as_ref(), &self.recon),
        ).await
            .map_err(|_| RepairError::Failed(format!("tries repair exceeded its {}s budget; configure cardano.kupo_url for an address-history backend", self.budget.as_secs())))?
            .map_err(|e| RepairError::Failed(e.to_string()))?;
        let walked = rebuilt.state.treasury_outpoint();
        if walked != head {
            return Err(RepairError::HeadMoved {
                walked,
                expected: head,
            });
        }
        install_pair(state_dir, &rebuilt.cpo, &rebuilt.spi).map_err(RepairError::Failed)?;
        let pending_kept = if matches!(status, TriesStatus::Unreadable { .. }) {
            None
        } else {
            drop_pending_record(state_dir)
        };
        Ok(Repaired {
            cpo_root: rebuilt.cpo.root(),
            spi_root: rebuilt.spi.root(),
            pending_kept,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint() -> bitcoin::OutPoint {
        "26b974ecda8c0a03c3d202d1236baacbf74bd630b75fa2694ebaefe15f19f1f6:0"
            .parse()
            .unwrap()
    }

    /// A record that cannot be removed is reported, not raised: a directory
    /// where the file should be is the failure a test can build portably.
    #[test]
    fn a_pending_record_that_cannot_be_removed_is_reported_not_raised() {
        let dir =
            std::env::temp_dir().join(format!("heimdall-tries-repair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let record = PendingTm::state_path(&dir);
        std::fs::create_dir(&record).unwrap();
        let kept = drop_pending_record(&dir).expect("reported");
        assert!(kept.contains("pending-tm.json"), "{kept}");
        assert!(record.exists());

        std::fs::remove_dir(&record).unwrap();
        std::fs::write(&record, b"{}").unwrap();
        assert_eq!(drop_pending_record(&dir), None);
        assert!(!record.exists());
        // Absent is the common case, and not a failure either.
        assert_eq!(drop_pending_record(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_event_leads_with_the_outcome_and_labels_the_old_state() {
        let mut repaired = Repaired {
            cpo_root: [0xe6; 32],
            spi_root: [0x82; 32],
            pending_kept: None,
        };
        let line = repaired.describe(outpoint(), "spi root 49bb != the chain's 8216");
        assert_eq!(
            line,
            format!(
                "tries rebuilt from chain history at treasury head {}; they now match the \
                 bridge-state singleton (cpo root {}, spi root {}). Before the rebuild: spi root \
                 49bb != the chain's 8216",
                outpoint(),
                "e6".repeat(32),
                "82".repeat(32)
            )
        );

        repaired.pending_kept = Some("remove /s/pending-tm.json: Read-only file system".into());
        let line = repaired.describe(outpoint(), "never seeded (cpo, spi absent)");
        assert!(
            line.ends_with(
                "Before the rebuild: never seeded (cpo, spi absent). The pending-movement record \
                 could not be removed (remove /s/pending-tm.json: Read-only file system) and \
                 stays; a fold must still reproduce the roots its movement committed, so it \
                 cannot move these tries anywhere the chain has not"
            ),
            "{line}"
        );
    }
}

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

#[async_trait]
pub trait TriesRepairer: Send + Sync + std::fmt::Debug {
    async fn repair(
        &self,
        state_dir: &Path,
        status: &TriesStatus,
        why: &str,
        head: bitcoin::OutPoint,
    ) -> Result<String, RepairError>;
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

#[async_trait]
impl TriesRepairer for ChainTriesRepairer {
    async fn repair(
        &self,
        state_dir: &Path,
        status: &TriesStatus,
        why: &str,
        head: bitcoin::OutPoint,
    ) -> Result<String, RepairError> {
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
        if !matches!(status, TriesStatus::Unreadable { .. }) {
            PendingTm::clear(state_dir).map_err(RepairError::Failed)?;
        }
        // `why` is the state BEFORE the rebuild, so it is labelled as such: after
        // "tries rebuilt", a bare "spi root X != the chain's Y" reads as the
        // rebuild's outcome. The roots named are the rebuilt ones, which
        // `reconstruct_both` has already held against the singleton.
        tracing::warn!(
            target: "heimdall::event",
            "tries rebuilt from chain history at treasury head {head}; they now match the \
             bridge-state singleton (cpo root {}, spi root {}). Before the rebuild: {why}",
            hex::encode(rebuilt.cpo.root()),
            hex::encode(rebuilt.spi.root())
        );
        Ok(why.to_string())
    }
}

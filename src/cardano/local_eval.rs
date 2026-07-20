//! Local Plutus phase-2 evaluation for fully assembled transactions.
//!
//! The Whisky evaluator expects the caller to provide every resolved UTxO that
//! can be referenced during validation. For fault-proof benchmarks this means
//! wallet inputs, script inputs, datum/reference inputs, and reference-script
//! UTxOs.

use std::{error::Error, fmt};

use uplc::tx::SlotConfig;
use whisky_common::{Action, EvalError, EvalResult, Network, UTxO};
use whisky_pallas::utils::evaluate_tx_scripts;

/// Default transaction execution-unit limits used by the DKG fault benchmarks.
pub const DEFAULT_TX_EX_UNIT_LIMITS: ExUnits = ExUnits {
    mem: 16_500_000,
    cpu: 10_000_000_000,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExUnits {
    pub mem: u64,
    pub cpu: u64,
}

impl ExUnits {
    #[must_use]
    pub fn exceeds(self, limits: Self) -> bool {
        self.mem > limits.mem || self.cpu > limits.cpu
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalEvalReport {
    pub actions: Vec<Action>,
    pub total: ExUnits,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LocalEvalError {
    Evaluator(String),
    ScriptFailures(Vec<EvalError>),
    ExUnitsExceeded { total: ExUnits, limits: ExUnits },
}

impl fmt::Display for LocalEvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluator(err) => write!(f, "{err}"),
            Self::ScriptFailures(errors) => {
                write!(f, "{} script evaluation error(s)", errors.len())?;
                for error in errors {
                    write!(
                        f,
                        "\n  {:?}[{}]: mem={} cpu={} {}",
                        error.tag,
                        error.index,
                        error.budget.mem,
                        error.budget.steps,
                        error.error_message
                    )?;
                }
                Ok(())
            }
            Self::ExUnitsExceeded { total, limits } => write!(
                f,
                "transaction ExUnits exceed limits: mem={} cpu={} limits_mem={} limits_cpu={}",
                total.mem, total.cpu, limits.mem, limits.cpu
            ),
        }
    }
}

impl Error for LocalEvalError {}

/// Evaluate all phase-2 scripts in a transaction and optionally enforce a total
/// transaction execution-unit budget.
pub fn evaluate_tx_phase2(
    tx_hex: &str,
    resolved_utxos: &[UTxO],
    network: &Network,
    slot_config: &SlotConfig,
    limits: Option<ExUnits>,
) -> Result<LocalEvalReport, LocalEvalError> {
    let results = evaluate_tx_scripts(tx_hex, resolved_utxos, &[], network, slot_config)
        .map_err(|err| LocalEvalError::Evaluator(err.to_string()))?;
    local_eval_report(results, limits)
}

pub fn local_eval_report(
    results: Vec<EvalResult>,
    limits: Option<ExUnits>,
) -> Result<LocalEvalReport, LocalEvalError> {
    let mut actions = Vec::new();
    let mut errors = Vec::new();

    for result in results {
        match result {
            EvalResult::Success(action) => actions.push(action),
            EvalResult::Error(error) => errors.push(error),
        }
    }

    if !errors.is_empty() {
        return Err(LocalEvalError::ScriptFailures(errors));
    }

    let total = actions
        .iter()
        .fold(ExUnits { mem: 0, cpu: 0 }, |sum, action| ExUnits {
            mem: sum.mem.saturating_add(action.budget.mem),
            cpu: sum.cpu.saturating_add(action.budget.steps),
        });

    if let Some(limits) = limits {
        if total.exceeds(limits) {
            return Err(LocalEvalError::ExUnitsExceeded { total, limits });
        }
    }

    Ok(LocalEvalReport { actions, total })
}

#[cfg(test)]
mod tests {
    use whisky_common::{Action, Budget, EvalError, EvalResult, RedeemerTag};

    use super::{ExUnits, LocalEvalError, local_eval_report};

    #[test]
    fn local_eval_report_sums_successes() {
        let report = local_eval_report(
            vec![
                EvalResult::Success(Action {
                    index: 0,
                    tag: RedeemerTag::Mint,
                    budget: Budget {
                        mem: 10,
                        steps: 100,
                    },
                }),
                EvalResult::Success(Action {
                    index: 1,
                    tag: RedeemerTag::Spend,
                    budget: Budget {
                        mem: 20,
                        steps: 200,
                    },
                }),
            ],
            Some(ExUnits { mem: 30, cpu: 300 }),
        )
        .unwrap();

        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.total, ExUnits { mem: 30, cpu: 300 });
    }

    #[test]
    fn local_eval_report_rejects_script_errors() {
        let error = EvalError {
            index: 0,
            tag: RedeemerTag::Mint,
            budget: Budget { mem: 4, steps: 5 },
            error_message: "boom".to_string(),
            logs: Vec::new(),
        };

        let err = local_eval_report(vec![EvalResult::Error(error.clone())], None).unwrap_err();

        assert_eq!(err, LocalEvalError::ScriptFailures(vec![error]));
    }

    #[test]
    fn local_eval_report_enforces_limits() {
        let err = local_eval_report(
            vec![EvalResult::Success(Action {
                index: 0,
                tag: RedeemerTag::Mint,
                budget: Budget {
                    mem: 31,
                    steps: 300,
                },
            })],
            Some(ExUnits { mem: 30, cpu: 300 }),
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalEvalError::ExUnitsExceeded {
                total: ExUnits { mem: 31, cpu: 300 },
                limits: ExUnits { mem: 30, cpu: 300 }
            }
        );
    }
}

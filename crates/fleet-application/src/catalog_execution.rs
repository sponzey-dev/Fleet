//! Pure target/capability preflight and immutable catalog Job provenance reads.

use crate::{CAPABILITY_SNAPSHOT_MAX_AGE, CatalogJobTargetSelection, select_dispatch_targets};
use fleet_domain::{
    Agent, AgentCapabilitySnapshot, AgentId, AgentStatus, CapabilitySnapshotStatus,
    CatalogRunbookProvenance, JobId, Runbook, RunbookTask, RuntimePrimitive, Selector,
};
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;

/// Safe classifications; no target data or capability payload is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogTargetError {
    InvalidSelection,
    DuplicateTargets,
    NoTargets,
    UnknownAgent,
    DisabledAgent,
    UnsupportedCapability,
    StaleCapability,
}

impl Display for CatalogTargetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSelection => "invalid catalog target selection",
            Self::DuplicateTargets => "catalog targets must be unique",
            Self::NoTargets => "catalog selection has no targets",
            Self::UnknownAgent => "catalog target is unknown",
            Self::DisabledAgent => "catalog target is disabled",
            Self::UnsupportedCapability => "catalog target lacks a required capability",
            Self::StaleCapability => "catalog target capability report is stale",
        })
    }
}
impl std::error::Error for CatalogTargetError {}

/// Resolves one target snapshot. Selectors exclude disabled Agents and retain
/// offline Agents; explicit IDs reject unknown, disabled and duplicate targets.
pub fn resolve_catalog_runbook_targets(
    agents: &[Agent],
    selection: &CatalogJobTargetSelection,
    explicit_ids: &[String],
    runbook_selector: &Selector,
) -> Result<Vec<String>, CatalogTargetError> {
    let ids = match selection {
        CatalogJobTargetSelection::ExplicitIds => {
            let mut seen = BTreeSet::new();
            for id in explicit_ids {
                AgentId::new(id).map_err(|_| CatalogTargetError::InvalidSelection)?;
                if !seen.insert(id) {
                    return Err(CatalogTargetError::DuplicateTargets);
                }
                let agent = agents
                    .iter()
                    .find(|a| a.id().as_str() == id)
                    .ok_or(CatalogTargetError::UnknownAgent)?;
                if agent.status() == AgentStatus::Disabled {
                    return Err(CatalogTargetError::DisabledAgent);
                }
            }
            explicit_ids.to_vec()
        }
        _ => {
            if !explicit_ids.is_empty() {
                return Err(CatalogTargetError::InvalidSelection);
            }
            let selector = match selection {
                CatalogJobTargetSelection::Selector(value) => {
                    Selector::parse(value).map_err(|_| CatalogTargetError::InvalidSelection)?
                }
                CatalogJobTargetSelection::MatchLabels(labels) => {
                    Selector::from_match_labels(labels.clone())
                        .map_err(|_| CatalogTargetError::InvalidSelection)?
                }
                CatalogJobTargetSelection::Runbook => runbook_selector.clone(),
                CatalogJobTargetSelection::ExplicitIds => {
                    return Err(CatalogTargetError::InvalidSelection);
                }
            };
            select_dispatch_targets(agents, &selector)
                .targets
                .into_iter()
                .map(|a| a.id().as_str().to_owned())
                .collect()
        }
    };
    if ids.is_empty() {
        return Err(CatalogTargetError::NoTargets);
    }
    Ok(ids)
}

/// Rejects known incompatible or stale reports before creation. Missing or
/// unknown reports keep the existing dispatch policy; Agent validation still applies.
pub fn validate_catalog_runbook_capability(
    snapshot: Option<AgentCapabilitySnapshot>,
    runbook: &Runbook,
    now: SystemTime,
) -> Result<(), CatalogTargetError> {
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let snapshot = snapshot.stale_if_older_than(now, CAPABILITY_SNAPSHOT_MAX_AGE);
    let mut primitives = vec![RuntimePrimitive::RunbookExecution];
    for task in &runbook.tasks {
        match task {
            RunbookTask::Package(_) => primitives.push(RuntimePrimitive::PackageInstall),
            RunbookTask::Service(_) => primitives.push(RuntimePrimitive::ServiceControl),
            RunbookTask::FileCopy(_) | RunbookTask::FileTemplate(_) => {
                primitives.push(RuntimePrimitive::FileCopy)
            }
            _ => {}
        }
    }
    for primitive in primitives {
        match snapshot.evaluate(primitive).status {
            CapabilitySnapshotStatus::Unsupported => {
                return Err(CatalogTargetError::UnsupportedCapability);
            }
            CapabilitySnapshotStatus::Stale => return Err(CatalogTargetError::StaleCapability),
            _ => {}
        }
    }
    Ok(())
}

/// Reads the immutable Job-owned snapshot, never the current active source.
pub trait CatalogRunbookJobQueryRepository {
    type Error;
    fn find_catalog_runbook_job_provenance(
        &self,
        job_id: &JobId,
    ) -> Result<Option<CatalogRunbookProvenance>, Self::Error>;
}

/// Returns the persisted snapshot, or absence for raw/unknown Jobs. The interface
/// separately checks Job existence and authorizes the read.
pub struct GetCatalogRunbookJobProvenance;
impl GetCatalogRunbookJobProvenance {
    pub fn execute<R: CatalogRunbookJobQueryRepository>(
        repo: &R,
        job_id: &JobId,
    ) -> Result<Option<CatalogRunbookProvenance>, R::Error> {
        repo.find_catalog_runbook_job_provenance(job_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CatalogJobTargetSelection;
    use fleet_domain::{AgentFingerprint, AgentIdentity, AgentLabel, AgentName, AgentPublicKey};

    fn agent(id: &str) -> Agent {
        let mut agent = Agent::new(
            AgentId::new(id).unwrap(),
            AgentName::new(id).unwrap(),
            AgentIdentity {
                public_key: AgentPublicKey::new("test-public").unwrap(),
                fingerprint: AgentFingerprint::new("0123456789abcdef").unwrap(),
            },
        );
        agent.set_labels(vec![AgentLabel::new("role", "web").unwrap()]);
        agent
    }

    #[test]
    fn catalog_preflight_rejects_invalid_explicit_targets_without_dropping_them() {
        let mut disabled = agent("disabled");
        disabled.disable();
        let agents = vec![agent("offline"), disabled];
        for (ids, expected) in [
            (vec!["missing".into()], CatalogTargetError::UnknownAgent),
            (vec!["disabled".into()], CatalogTargetError::DisabledAgent),
            (
                vec!["offline".into(), "offline".into()],
                CatalogTargetError::DuplicateTargets,
            ),
            (vec![], CatalogTargetError::NoTargets),
        ] {
            assert_eq!(
                resolve_catalog_runbook_targets(
                    &agents,
                    &CatalogJobTargetSelection::ExplicitIds,
                    &ids,
                    &Selector::parse("role=web").unwrap()
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn catalog_preflight_preserves_explicit_order_and_selector_offline_semantics() {
        let mut disabled = agent("disabled");
        disabled.disable();
        let agents = vec![agent("second"), agent("first"), disabled];
        let selector = Selector::parse("role=web").unwrap();
        let explicit = resolve_catalog_runbook_targets(
            &agents,
            &CatalogJobTargetSelection::ExplicitIds,
            &["first".into(), "second".into()],
            &selector,
        )
        .unwrap();
        assert_eq!(explicit, vec!["first", "second"]);
        for selection in [
            CatalogJobTargetSelection::Runbook,
            CatalogJobTargetSelection::Selector("role=web".into()),
            CatalogJobTargetSelection::MatchLabels(std::collections::BTreeMap::from([(
                "role".into(),
                "web".into(),
            )])),
        ] {
            assert_eq!(
                resolve_catalog_runbook_targets(&agents, &selection, &[], &selector).unwrap(),
                vec!["second", "first"]
            );
        }
    }

    #[test]
    fn catalog_preflight_checks_known_capabilities_and_each_runbook_primitive() {
        use fleet_domain::{AgentCapability, AgentRuntimeProfile, PackageManager, PrivilegeLevel};
        use std::time::Duration;
        let now = std::time::UNIX_EPOCH + CAPABILITY_SNAPSHOT_MAX_AGE + Duration::from_secs(1000);
        let runbook = fleet_domain::parse_runbook_document("apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: sample\nselector: role=web\nsteps:\n  - id: install\n    package:\n      name: nginx\n      state: present\n").unwrap();
        assert_eq!(
            validate_catalog_runbook_capability(None, &runbook, now),
            Ok(())
        );
        assert_eq!(
            validate_catalog_runbook_capability(
                Some(AgentCapabilitySnapshot::unknown()),
                &runbook,
                now
            ),
            Ok(())
        );
        let profile = |caps| {
            AgentRuntimeProfile::new(PrivilegeLevel::Root, Some(PackageManager::Apt), None, caps)
        };
        assert_eq!(
            validate_catalog_runbook_capability(
                Some(AgentCapabilitySnapshot::reported(profile(vec![]), now)),
                &runbook,
                now
            ),
            Err(CatalogTargetError::UnsupportedCapability)
        );
        assert_eq!(
            validate_catalog_runbook_capability(
                Some(AgentCapabilitySnapshot::reported(
                    profile(vec![AgentCapability::RunbookExecution]),
                    now
                )),
                &runbook,
                now
            ),
            Err(CatalogTargetError::UnsupportedCapability)
        );
        let capable = profile(vec![
            AgentCapability::RunbookExecution,
            AgentCapability::PackageInstall,
        ]);
        assert_eq!(
            validate_catalog_runbook_capability(
                Some(AgentCapabilitySnapshot::reported(capable.clone(), now)),
                &runbook,
                now
            ),
            Ok(())
        );
        assert_eq!(
            validate_catalog_runbook_capability(
                Some(AgentCapabilitySnapshot::reported(
                    capable,
                    std::time::UNIX_EPOCH
                )),
                &runbook,
                now
            ),
            Err(CatalogTargetError::StaleCapability)
        );
    }
}

//! Shared validation for the `aiken_design_patterns` linked-list snapshots that
//! both the SPO registry ([`super::registry`]) and the ban list
//! ([`super::ban_list`]) reconstruct from on-chain UTxOs.
//!
//! The two lists deliberately keep their OWN reconstruction + insert-planning:
//! they differ in the key↔asset-name codec (the registry key *is* the asset
//! name; a ban node's asset name is `"ban/" || key`), the node-data type and
//! its validation, the error type, and empty-list semantics. Generalizing all
//! of that for two instantiations would be the wrong abstraction.
//!
//! What they share exactly — and what a bug would otherwise have to be fixed in
//! twice — is the chain-walk invariant: following the links from the root must
//! visit every node once, in strictly ascending key order. That lives here.

/// Why a links-chain is not a single well-formed ascending list. The callers
/// map these onto their own error enums.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// A hop landed on a key `<=` the previous one (a cycle, or not strictly
    /// ascending).
    NotAscending(Vec<u8>),
    /// A link points at a key with no corresponding node.
    BrokenLink(Vec<u8>),
    /// `n` nodes are not reachable from the root (orphans / a fork).
    Unreachable(usize),
}

/// Walk the links from `root_link`: every hop must land on a known node
/// (`link_of(key)` returns `Some(that_node's_link)`) whose key is strictly
/// greater than the previous hop's, and the walk must visit all `node_count`
/// nodes. `link_of` returning `None` means the link is dangling (no such node).
pub fn validate_chain<'a>(
    root_link: Option<&'a [u8]>,
    node_count: usize,
    link_of: impl Fn(&[u8]) -> Option<Option<&'a [u8]>>,
) -> Result<(), ChainError> {
    let mut visited = 0usize;
    let mut prev: Option<&[u8]> = None;
    let mut cursor = root_link;
    while let Some(key) = cursor {
        if prev.is_some_and(|p| key <= p) {
            return Err(ChainError::NotAscending(key.to_vec()));
        }
        let link = link_of(key).ok_or_else(|| ChainError::BrokenLink(key.to_vec()))?;
        visited += 1;
        prev = Some(key);
        cursor = link;
    }
    if visited != node_count {
        return Err(ChainError::Unreachable(node_count - visited));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // A tiny chain harness: nodes keyed by Vec<u8>, each with an optional link.
    fn chain(root: Option<&[u8]>, nodes: &[(&[u8], Option<&[u8]>)]) -> Result<(), ChainError> {
        let map: BTreeMap<Vec<u8>, Option<Vec<u8>>> = nodes
            .iter()
            .map(|(k, l)| (k.to_vec(), l.map(<[u8]>::to_vec)))
            .collect();
        validate_chain(root, map.len(), |k| map.get(k).map(|l| l.as_deref()))
    }

    #[test]
    fn accepts_well_formed_chain() {
        // root -> a -> b -> c, ascending.
        assert!(
            chain(
                Some(b"a"),
                &[(b"a", Some(b"b")), (b"b", Some(b"c")), (b"c", None),],
            )
            .is_ok()
        );
        // empty (no nodes, no link) is a valid chain.
        assert!(chain(None, &[]).is_ok());
    }

    #[test]
    fn rejects_malformed_chains() {
        // not ascending (b then a).
        assert!(matches!(
            chain(Some(b"b"), &[(b"b", Some(b"a")), (b"a", None)]),
            Err(ChainError::NotAscending(_))
        ));
        // link to absent node.
        assert!(matches!(
            chain(Some(b"z"), &[(b"a", None)]),
            Err(ChainError::BrokenLink(_))
        ));
        // orphan: node `b` not reachable from root -> a -> None.
        assert!(matches!(
            chain(Some(b"a"), &[(b"a", None), (b"b", None)]),
            Err(ChainError::Unreachable(1))
        ));
        // cycle is caught by the strictly-ascending rule (a -> a).
        assert!(matches!(
            chain(Some(b"a"), &[(b"a", Some(b"a"))]),
            Err(ChainError::NotAscending(_))
        ));
    }
}

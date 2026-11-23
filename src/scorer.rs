use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};

use crate::error::WotError;
use crate::graph::{EgoGraphCache, level_to_factor};
use crate::identity::{Did, canonicalize_did};
use crate::provider_filter::StoredProviderFilter;
use crate::register::WotPolicy;

pub const MAX_CANDIDATE_PATHS: usize = 32;
pub const MIN_PATH_PROBABILITY: f64 = 0.005;

/// An evaluated trust path connecting `self_did` to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPath {
    pub hops: Vec<Did>,
    pub edge_levels: Vec<u8>,
    pub path_score: f64,
}

/// The result of evaluating network trust towards an identity or voucher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvaluation {
    /// Calculated trust score in [0.0, 1.0].
    pub score: f64,
    /// Shortest hop distance from self (None if unreachable).
    pub shortest_hops: Option<u8>,
    /// Independent candidate paths considered during evaluation.
    pub paths: Vec<TrustPath>,
    /// Issuance timestamp (`iat`) of the oldest third-party list used along the paths.
    pub oldest_list_iat: Option<u64>,
    /// True if evaluation was immediately blocked due to known double-spending / SST V4 conflict.
    pub blocked_by_offender: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EdgeKey {
    from: u32,
    to: u32,
}

struct RawPath {
    node_ids: Vec<u32>,
    edge_levels: Vec<u8>,
    edge_keys: Vec<EdgeKey>,
    prob_product: f64,
    oldest_iat: Option<u64>,
}

/// Computes the exact probability union of paths using Shannon expansion / factoring.
///
/// Guaranteed to prevent bottleneck over-counting (e.g. 1 link -> 30 parallel Sybils <= 0.30).
pub fn exact_path_union_prob(paths: &[Vec<usize>], edge_probs: &[f64], depth: usize) -> f64 {
    // 1. Any empty path means that all its edges were already conditioned to true (1.0).
    if paths.iter().any(|p| p.is_empty()) {
        return 1.0;
    }

    // 2. No paths left means target is unreachable under this conditioning.
    if paths.is_empty() {
        return 0.0;
    }

    // 3. Single path base case.
    if paths.len() == 1 {
        return paths[0].iter().map(|&e| edge_probs[e]).product();
    }

    // 4. Subsumption reduction: if Pa is a subset of Pb, Pb can be dropped.
    let mut reduced = Vec::with_capacity(paths.len());
    for (i, p_i) in paths.iter().enumerate() {
        let mut subsumed = false;
        for (j, p_j) in paths.iter().enumerate() {
            if i != j {
                let is_subset = p_j.len() <= p_i.len() && p_j.iter().all(|e| p_i.contains(e));
                if is_subset && (p_j.len() < p_i.len() || j < i) {
                    subsumed = true;
                    break;
                }
            }
        }
        if !subsumed {
            reduced.push(p_i.clone());
        }
    }
    let paths = reduced;

    if paths.is_empty() {
        return 0.0;
    }
    if paths.len() == 1 {
        return paths[0].iter().map(|&e| edge_probs[e]).product();
    }

    // 5. Disjoint connected components decomposition.
    let mut parent: Vec<usize> = (0..paths.len()).collect();
    fn find(p: &mut [usize], mut i: usize) -> usize {
        while p[i] != i {
            p[i] = p[p[i]];
            i = p[i];
        }
        i
    }
    fn union(p: &mut [usize], a: usize, b: usize) {
        let root_a = find(p, a);
        let root_b = find(p, b);
        if root_a != root_b {
            p[root_a] = root_b;
        }
    }

    for i in 0..paths.len() {
        for j in (i + 1)..paths.len() {
            if paths[i].iter().any(|e| paths[j].contains(e)) {
                union(&mut parent, i, j);
            }
        }
    }

    let mut component_map: HashMap<usize, Vec<Vec<usize>>> = HashMap::new();
    for (i, p_i) in paths.iter().enumerate() {
        let root = find(&mut parent, i);
        component_map.entry(root).or_default().push(p_i.clone());
    }

    if component_map.len() > 1 {
        let mut unreliability = 1.0;
        for comp_paths in component_map.values() {
            let comp_prob = exact_path_union_prob(comp_paths, edge_probs, depth + 1);
            unreliability *= 1.0 - comp_prob;
        }
        return (1.0 - unreliability).clamp(0.0, 1.0);
    }

    // 6. Find pivot edge e* with maximal frequency.
    let mut edge_counts = HashMap::new();
    for p in &paths {
        for &e in p {
            *edge_counts.entry(e).or_insert(0usize) += 1;
        }
    }

    let mut best_edge = 0;
    let mut max_count = 0;
    for (&e, &cnt) in &edge_counts {
        if cnt > max_count || (cnt == max_count && e < best_edge) {
            max_count = cnt;
            best_edge = e;
        }
    }

    // If max_count <= 1, all paths are mutually edge-disjoint!
    if max_count <= 1 {
        let mut unreliability = 1.0;
        for p in &paths {
            let p_prob: f64 = p.iter().map(|&e| edge_probs[e]).product();
            unreliability *= 1.0 - p_prob;
        }
        return (1.0 - unreliability).clamp(0.0, 1.0);
    }

    // 7. Shannon expansion on pivot edge e* (with recursion guard depth < 16).
    if depth >= 16 {
        // Fallback: disjoint approximation
        let mut unreliability = 1.0;
        for p in &paths {
            let p_prob: f64 = p.iter().map(|&e| edge_probs[e]).product();
            unreliability *= 1.0 - p_prob;
        }
        return (1.0 - unreliability).clamp(0.0, 1.0);
    }

    let p_pivot = edge_probs[best_edge];

    // Branch 1: best_edge = 1 (remove best_edge from all paths containing it)
    let branch1: Vec<Vec<usize>> = paths
        .iter()
        .map(|p| p.iter().copied().filter(|&e| e != best_edge).collect())
        .collect();

    // Branch 0: best_edge = 0 (drop all paths containing best_edge)
    let branch0: Vec<Vec<usize>> = paths
        .iter()
        .filter(|p| !p.contains(&best_edge))
        .cloned()
        .collect();

    let r1 = exact_path_union_prob(&branch1, edge_probs, depth + 1);
    let r0 = exact_path_union_prob(&branch0, edge_probs, depth + 1);

    (p_pivot * r1 + (1.0 - p_pivot) * r0).clamp(0.0, 1.0)
}

/// Evaluates network trust from `graph` to `target_did` or a voucher with optional guarantors.
pub fn evaluate_trust(
    graph: &EgoGraphCache,
    policy: &WotPolicy,
    creator_id: &str,
    guarantor_ids: &[&str],
    is_known_offender: bool,
    now_secs: Option<u64>,
) -> Result<TrustEvaluation, WotError> {
    evaluate_trust_with_providers(
        graph,
        policy,
        None,
        creator_id,
        guarantor_ids,
        is_known_offender,
        now_secs,
    )
}

/// Evaluates network trust from `graph` with optional provider filter seals.
pub fn evaluate_trust_with_providers(
    graph: &EgoGraphCache,
    policy: &WotPolicy,
    provider_filters: Option<&BTreeMap<Did, StoredProviderFilter>>,
    creator_id: &str,
    guarantor_ids: &[&str],
    is_known_offender: bool,
    now_secs: Option<u64>,
) -> Result<TrustEvaluation, WotError> {
    if is_known_offender {
        return Ok(TrustEvaluation {
            score: 0.0,
            shortest_hops: None,
            paths: Vec::new(),
            oldest_list_iat: None,
            blocked_by_offender: true,
        });
    }

    let canonical_creator = canonicalize_did(creator_id)?;

    if canonical_creator == graph.self_did {
        return Ok(TrustEvaluation {
            score: 1.0,
            shortest_hops: Some(0),
            paths: Vec::new(),
            oldest_list_iat: None,
            blocked_by_offender: false,
        });
    }

    evaluate_trust_internal(
        graph,
        policy,
        provider_filters,
        0,
        &canonical_creator,
        guarantor_ids,
        now_secs,
    )
}

/// Evaluates network trust from an observer's perspective towards a voucher given its creator and optional guarantors.
pub fn evaluate_trust_from_observer(
    graph: &EgoGraphCache,
    policy: &WotPolicy,
    observer_did: &str,
    creator_id: &str,
    guarantor_ids: &[&str],
    is_known_offender: bool,
    now_secs: Option<u64>,
) -> Result<TrustEvaluation, WotError> {
    if is_known_offender {
        return Ok(TrustEvaluation {
            score: 0.0,
            shortest_hops: None,
            paths: Vec::new(),
            oldest_list_iat: None,
            blocked_by_offender: true,
        });
    }

    let canonical_observer = canonicalize_did(observer_did)?;
    let canonical_creator = canonicalize_did(creator_id)?;

    if canonical_observer == graph.self_did {
        return evaluate_trust(
            graph,
            policy,
            creator_id,
            guarantor_ids,
            is_known_offender,
            now_secs,
        );
    }

    if canonical_observer == canonical_creator {
        return Ok(TrustEvaluation {
            score: 1.0,
            shortest_hops: Some(0),
            paths: Vec::new(),
            oldest_list_iat: None,
            blocked_by_offender: false,
        });
    }

    let observer_node_id = match graph.did_to_id.get(&canonical_observer) {
        Some(&id) => id,
        None => {
            return Ok(TrustEvaluation {
                score: 0.0,
                shortest_hops: None,
                paths: Vec::new(),
                oldest_list_iat: None,
                blocked_by_offender: false,
            });
        }
    };

    evaluate_trust_internal(
        graph,
        policy,
        None,
        observer_node_id,
        &canonical_creator,
        guarantor_ids,
        now_secs,
    )
}

fn evaluate_trust_internal(
    graph: &EgoGraphCache,
    policy: &WotPolicy,
    provider_filters: Option<&BTreeMap<Did, StoredProviderFilter>>,
    start_node_id: u32,
    canonical_creator: &str,
    guarantor_ids: &[&str],
    now_secs: Option<u64>,
) -> Result<TrustEvaluation, WotError> {
    // Clone graph to allow adding temporary guarantor bridges and provider seals
    let mut eval_graph = graph.clone();
    let creator_node_id = eval_graph.get_or_create_node(canonical_creator);

    let mut dedup_guarantors = Vec::new();
    let mut seen_g = HashSet::new();
    for &g in guarantor_ids {
        let can_g = canonicalize_did(g)?;
        if can_g != canonical_creator && seen_g.insert(can_g.clone()) {
            dedup_guarantors.push(can_g);
        }
    }

    // Inject provider filters when evaluating from local perspective (start_node_id == 0)
    if start_node_id == 0
        && let Some(filters) = provider_filters
    {
        for (prov_did, prov) in filters {
            let own_contact_lvl = eval_graph
                .did_to_id
                .get(prov_did)
                .and_then(|&p_id| {
                    eval_graph
                        .outgoing
                        .first()
                        .and_then(|edges| edges.iter().find(|e| e.to == p_id).map(|e| e.level))
                })
                .unwrap_or(0);

            let user_level = prov.local_trust_level.max(own_contact_lvl);
            if user_level == 0 {
                continue;
            }

            let prov_node_id = eval_graph.get_or_create_node(prov_did);
            eval_graph.add_or_update_edge(0, prov_node_id, user_level, prov.payload.iat);

            // Check creator
            if let Some(cert_lvl) = prov.certified_level(canonical_creator) {
                eval_graph.add_or_update_edge(
                    prov_node_id,
                    creator_node_id,
                    cert_lvl,
                    prov.payload.iat,
                );
            }

            // Check guarantors
            for g_did in &dedup_guarantors {
                if let Some(cert_lvl) = prov.certified_level(g_did) {
                    let g_node_id = eval_graph.get_or_create_node(g_did);
                    eval_graph.add_or_update_edge(
                        prov_node_id,
                        g_node_id,
                        cert_lvl,
                        prov.payload.iat,
                    );
                }
            }
        }
    }

    // Precalculate base edge probabilities and cache edge attributes before temporary bridges
    let mut edge_prob_map: HashMap<EdgeKey, f64> = HashMap::new();
    let mut edge_iat_map: HashMap<EdgeKey, u64> = HashMap::new();
    let mut edge_level_map: HashMap<EdgeKey, u8> = HashMap::new();

    for from in 0..eval_graph.outgoing.len() {
        for edge in &eval_graph.outgoing[from] {
            let key = EdgeKey {
                from: edge.from,
                to: edge.to,
            };
            let base_factor = level_to_factor(edge.level);

            let prob = if edge.from == 0 {
                base_factor
            } else if let (Some(hl), Some(now)) = (policy.freshness_half_life_secs, now_secs) {
                if hl > 0 {
                    let dt = now.saturating_sub(edge.list_iat);
                    if dt > policy.freshness_grace_secs {
                        let excess = (dt - policy.freshness_grace_secs) as f64;
                        base_factor * 2.0_f64.powf(-excess / (hl as f64))
                    } else {
                        base_factor
                    }
                } else {
                    base_factor
                }
            } else {
                base_factor
            };

            edge_prob_map.insert(key.clone(), prob);
            edge_iat_map.insert(key.clone(), edge.list_iat);
            edge_level_map.insert(key, edge.level);
        }
    }

    // Add temporary guarantor bridges (guarantor -> creator), upgrading probability via max(...)
    let gw = policy.guarantor_weight.clamp(0.0, 1.0);
    if gw > 0.0 {
        for g_did in &dedup_guarantors {
            let g_node_id = eval_graph.get_or_create_node(g_did);
            if g_node_id == creator_node_id {
                continue;
            }
            let key = EdgeKey {
                from: g_node_id,
                to: creator_node_id,
            };
            if let Some(existing_prob) = edge_prob_map.get_mut(&key) {
                if gw > *existing_prob {
                    *existing_prob = gw;
                    edge_level_map.insert(key.clone(), 3);
                    edge_iat_map.remove(&key);
                }
            } else {
                eval_graph.add_or_update_edge(g_node_id, creator_node_id, 3, now_secs.unwrap_or(0));
                edge_prob_map.insert(key.clone(), gw);
                edge_level_map.insert(key, 3);
            }
        }
    }

    // Reverse-BFS reachability from creator_node_id + bounded Best-First Search (prevents Sybil-clique DFS DoS)
    const MAX_SEARCH_EXPANSIONS: usize = 8_192;
    const MAX_HEAP_STATES: usize = 32_768;

    let num_nodes = eval_graph.outgoing.len();
    let mut rev_adj: Vec<Vec<u32>> = vec![Vec::new(); num_nodes];
    for edges in &eval_graph.outgoing {
        for edge in edges {
            let key = EdgeKey {
                from: edge.from,
                to: edge.to,
            };
            if edge_prob_map.get(&key).copied().unwrap_or(0.0) >= MIN_PATH_PROBABILITY
                && (edge.to as usize) < num_nodes
            {
                rev_adj[edge.to as usize].push(edge.from);
            }
        }
    }

    let mut min_hops_to_target = vec![u8::MAX; num_nodes];
    if (creator_node_id as usize) < num_nodes {
        let mut bfs_q = VecDeque::new();
        min_hops_to_target[creator_node_id as usize] = 0;
        bfs_q.push_back(creator_node_id);
        while let Some(node) = bfs_q.pop_front() {
            let next_d = min_hops_to_target[node as usize].saturating_add(1);
            for &prev in &rev_adj[node as usize] {
                if (prev as usize) < num_nodes && min_hops_to_target[prev as usize] == u8::MAX {
                    min_hops_to_target[prev as usize] = next_d;
                    bfs_q.push_back(prev);
                }
            }
        }
    }

    #[derive(Clone)]
    struct SearchState {
        prob: f64,
        nodes: Vec<u32>,
        levels: Vec<u8>,
        edge_keys: Vec<EdgeKey>,
    }

    impl PartialEq for SearchState {
        fn eq(&self, other: &Self) -> bool {
            self.prob.total_cmp(&other.prob) == std::cmp::Ordering::Equal
                && self.nodes == other.nodes
        }
    }

    impl Eq for SearchState {}

    impl Ord for SearchState {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.prob
                .total_cmp(&other.prob)
                .then_with(|| other.nodes.len().cmp(&self.nodes.len()))
                .then_with(|| other.nodes.cmp(&self.nodes))
        }
    }

    impl PartialOrd for SearchState {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    let mut raw_paths: Vec<RawPath> = Vec::new();
    let max_depth = policy.max_eval_depth as usize;

    if (start_node_id as usize) < num_nodes
        && min_hops_to_target[start_node_id as usize] != u8::MAX
        && (min_hops_to_target[start_node_id as usize] as usize) <= max_depth
    {
        let mut heap = BinaryHeap::new();
        heap.push(SearchState {
            prob: 1.0,
            nodes: vec![start_node_id],
            levels: Vec::new(),
            edge_keys: Vec::new(),
        });

        let mut expansions = 0usize;
        while let Some(state) = heap.pop() {
            let curr = *state
                .nodes
                .last()
                .expect("SearchState always has >= 1 node");
            if curr == creator_node_id {
                if state.prob >= MIN_PATH_PROBABILITY {
                    let mut oldest_iat: Option<u64> = None;
                    for k in &state.edge_keys {
                        if let Some(&iat) = (k.from != 0).then(|| edge_iat_map.get(k)).flatten() {
                            oldest_iat = Some(match oldest_iat {
                                None => iat,
                                Some(prev) => prev.min(iat),
                            });
                        }
                    }

                    raw_paths.push(RawPath {
                        node_ids: state.nodes,
                        edge_levels: state.levels,
                        edge_keys: state.edge_keys,
                        prob_product: state.prob,
                        oldest_iat,
                    });
                    if raw_paths.len() >= MAX_CANDIDATE_PATHS {
                        break;
                    }
                }
                continue;
            }

            expansions += 1;
            if expansions > MAX_SEARCH_EXPANSIONS {
                break;
            }

            let hops_so_far = state.nodes.len() - 1;
            if hops_so_far >= max_depth {
                continue;
            }

            if (curr as usize) < eval_graph.outgoing.len() {
                for edge in &eval_graph.outgoing[curr as usize] {
                    let to_idx = edge.to as usize;
                    let rem = if to_idx < min_hops_to_target.len() {
                        min_hops_to_target[to_idx]
                    } else {
                        u8::MAX
                    };
                    if rem == u8::MAX || hops_so_far + 1 + (rem as usize) > max_depth {
                        continue;
                    }
                    if state.nodes.contains(&edge.to) {
                        continue;
                    }

                    let key = EdgeKey {
                        from: edge.from,
                        to: edge.to,
                    };
                    let p = edge_prob_map.get(&key).copied().unwrap_or(0.0);
                    let next_prob = state.prob * p;
                    if next_prob >= MIN_PATH_PROBABILITY {
                        let mut next_nodes = state.nodes.clone();
                        next_nodes.push(edge.to);
                        let mut next_levels = state.levels.clone();
                        next_levels.push(edge_level_map.get(&key).copied().unwrap_or(edge.level));
                        let mut next_keys = state.edge_keys.clone();
                        next_keys.push(key);

                        heap.push(SearchState {
                            prob: next_prob,
                            nodes: next_nodes,
                            levels: next_levels,
                            edge_keys: next_keys,
                        });
                    }
                }
            }

            if heap.len() >= MAX_HEAP_STATES {
                let mut drained: Vec<SearchState> = heap.drain().collect();
                drained.sort_unstable_by(|a, b| b.cmp(a));
                drained.truncate(MAX_HEAP_STATES / 2);
                heap = BinaryHeap::from(drained);
            }
        }
    }

    if raw_paths.is_empty() {
        return Ok(TrustEvaluation {
            score: 0.0,
            shortest_hops: None,
            paths: Vec::new(),
            oldest_list_iat: None,
            blocked_by_offender: false,
        });
    }

    // Sort descending by prob_product
    raw_paths.sort_by(|a, b| {
        b.prob_product
            .partial_cmp(&a.prob_product)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    raw_paths.truncate(MAX_CANDIDATE_PATHS);

    // Collect all unique edges in the candidate paths
    let mut edge_indexer: HashMap<EdgeKey, usize> = HashMap::new();
    let mut edge_probs: Vec<f64> = Vec::new();

    for rp in &raw_paths {
        for k in &rp.edge_keys {
            if !edge_indexer.contains_key(k) {
                let id = edge_probs.len();
                edge_indexer.insert(k.clone(), id);
                edge_probs.push(edge_prob_map.get(k).copied().unwrap_or(0.0));
            }
        }
    }

    let indexed_paths: Vec<Vec<usize>> = raw_paths
        .iter()
        .map(|rp| rp.edge_keys.iter().map(|k| edge_indexer[k]).collect())
        .collect();

    let score = exact_path_union_prob(&indexed_paths, &edge_probs, 0);

    let shortest_hops = raw_paths.iter().map(|p| (p.node_ids.len() - 1) as u8).min();

    let mut oldest_list_iat: Option<u64> = None;
    for p in &raw_paths {
        if let Some(iat) = p.oldest_iat {
            oldest_list_iat = Some(match oldest_list_iat {
                None => iat,
                Some(prev) => prev.min(iat),
            });
        }
    }

    let trust_paths: Vec<TrustPath> = raw_paths
        .into_iter()
        .map(|rp| {
            let hops = rp
                .node_ids
                .iter()
                .map(|&id| eval_graph.id_to_did[id as usize].clone())
                .collect();
            TrustPath {
                hops,
                edge_levels: rp.edge_levels,
                path_score: rp.prob_product,
            }
        })
        .collect();

    Ok(TrustEvaluation {
        score,
        shortest_hops,
        paths: trust_paths,
        oldest_list_iat,
        blocked_by_offender: false,
    })
}

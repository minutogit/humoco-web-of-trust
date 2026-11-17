use crate::identity::Did;
use crate::register::OwnTrustEntry;
use crate::sd_jwt::StoredSdJwt;
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Maps trust level (0..3) to edge trust probability factor.
pub fn level_to_factor(level: u8) -> f64 {
    match level {
        0 => 0.0,
        1 => 0.30,
        2 => 0.60,
        3 => 0.85,
        _ => 0.0,
    }
}

/// A directed edge in the ego trust graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: u32,
    pub to: u32,
    pub level: u8,
    pub list_iat: u64,
}

/// Compact in-memory directed graph for BFS reachability and path finding.
/// Node 0 is always `self_did`. Only edges with `level >= 1` are contained.
#[derive(Debug, Clone)]
pub struct EgoGraphCache {
    pub self_did: Did,
    pub did_to_id: HashMap<Did, u32>,
    pub id_to_did: Vec<Did>,
    pub outgoing: Vec<Vec<GraphEdge>>,
}

impl EgoGraphCache {
    /// Creates an empty graph with node 0 reserved for `self_did`.
    pub fn new(self_did: Did) -> Self {
        let mut did_to_id = HashMap::new();
        did_to_id.insert(self_did.clone(), 0);
        let id_to_did = vec![self_did.clone()];
        let outgoing = vec![Vec::new()];

        Self {
            self_did,
            did_to_id,
            id_to_did,
            outgoing,
        }
    }

    /// Builds the `EgoGraphCache` from `own_contacts` and verified `raw_list_store`.
    pub fn build(
        self_did: &str,
        own_contacts: &BTreeMap<Did, OwnTrustEntry>,
        raw_list_store: &BTreeMap<Did, StoredSdJwt>,
    ) -> Self {
        let mut graph = Self::new(self_did.to_string());

        // 1. Direct own contacts with level >= 1
        for (target_did, entry) in own_contacts {
            if entry.level >= 1 {
                let to_id = graph.get_or_create_node(target_did);
                graph.add_or_update_edge(0, to_id, entry.level, entry.updated_at);
            }
        }

        // 2. Incoming third-party lists
        for (iss, stored) in raw_list_store {
            let from_id = graph.get_or_create_node(iss);
            for d in stored.disclosures.values() {
                if d.level >= 1 {
                    let to_id = graph.get_or_create_node(&d.target_did);
                    graph.add_or_update_edge(from_id, to_id, d.level, stored.iat);
                }
            }
        }

        graph
    }

    /// Returns existing node ID or registers a new node.
    pub fn get_or_create_node(&mut self, did: &str) -> u32 {
        if let Some(&id) = self.did_to_id.get(did) {
            id
        } else {
            let new_id = self.id_to_did.len() as u32;
            self.did_to_id.insert(did.to_string(), new_id);
            self.id_to_did.push(did.to_string());
            self.outgoing.push(Vec::new());
            new_id
        }
    }

    /// Adds an edge or updates it if a stronger edge already exists between `from` and `to`.
    pub fn add_or_update_edge(&mut self, from: u32, to: u32, level: u8, list_iat: u64) {
        if from == to || level == 0 {
            return;
        }

        if let Some(existing) = self.outgoing[from as usize].iter_mut().find(|e| e.to == to) {
            if level > existing.level || (level == existing.level && list_iat > existing.list_iat) {
                existing.level = level;
                existing.list_iat = list_iat;
            }
        } else {
            self.outgoing[from as usize].push(GraphEdge {
                from,
                to,
                level,
                list_iat,
            });
        }
    }

    /// Computes the shortest distance in hops from node 0 (`self_did`) to all reachable nodes.
    pub fn shortest_distances_from_self(&self) -> HashMap<u32, u8> {
        let mut distances = HashMap::new();
        let mut queue = VecDeque::new();

        distances.insert(0, 0);
        queue.push_back((0, 0));

        while let Some((curr, dist)) = queue.pop_front() {
            if (curr as usize) < self.outgoing.len() {
                for edge in &self.outgoing[curr as usize] {
                    if let std::collections::hash_map::Entry::Vacant(e) = distances.entry(edge.to) {
                        let next_dist = dist + 1;
                        e.insert(next_dist);
                        queue.push_back((edge.to, next_dist));
                    }
                }
            }
        }

        distances
    }

    /// Shortest distance from `self_did` to a target DID.
    pub fn shortest_distance_to_did(&self, target_did: &str) -> Option<u8> {
        self.did_to_id
            .get(target_did)
            .and_then(|id| self.shortest_distances_from_self().get(id).copied())
    }
}

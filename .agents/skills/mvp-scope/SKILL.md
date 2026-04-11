---
name: mvp-scope
description: Critical context about the MVP scope, limitations, and design decisions for the Web of Trust. You MUST read this before working on WOT tasks.
---

# SKILL: WoT MVP Scope & Design Decisions

This skill provides the binding constraints and architectural decisions for the initial Minimal Viable Product (MVP) of the Humoco Web of Trust.

## 1. Core Principles
*   **Asymmetric Trust**: Trust is unilateral. User A can trust User B, but User B does not automatically trust User A. The local `LocalTrustGraph` and `TrustManifest` are built upon an asymmetric view of the world.
*   **Decoupled Trust Expression**: Users can sign trust attestations (SD-JWTs) for *any* DID they know, not just through a physical (F2F) protocol.
*   **Data-Driven Hop Depth**: The client does not enforce an artificial global limit on hops (e.g., "max 2 hops"). Instead, the client calculates paths as far as its local data allows. The limiting factor is how much data (Envelopes, Forwarded Attestations) is shared during sync.

## 2. Sync Modalities (MVP vs. Future)
*   **MVP Transport**:
    1.  **Face-to-Face (F2F)**: QR codes are the primary mechanism for exchanging initial DID information and establishing the first connection in person.
    2.  **Online Direct P2P**: Users must be able to periodically delta-sync over an online connection when available, establishing direct connections.
*   **NOT in MVP (Deferred)**: BLE/NFC (too complex for v1), Relay Servers/Mailboxes (no background sync infrastructure yet), complex Gossip Protocols (only direct contact sync).

## 3. The Synchronization Protocol (WOT-007)
*   **Delta-Sync**: Since data volumes can grow quickly (~100KB for 50 contacts), clients must exchange version numbers and epochs *before* exchanging full payloads.
*   **Data to Sync**:
    *   Own newly signed/updated IdentityEnvelope.
    *   Fresh SD-JWTs (Trust Attestations).
    *   Forwarded Attestations (proofs from friends of friends).
    *   Revocations.
    *   IdentityEnvelopes from downstream contacts (to allow extended path calculation).

## 4. The Trust Establishment Protocol (WOT-006)
*   When A decides to trust B, they must determine what existing data to send to B.
*   **Privacy Consideration**: Should A send the IdentityEnvelopes of A's friends to B immediately? This exposes A's local graph topology. The protocol must define exactly what payload is transferred.

## 5. Summary of Task Dependencies
When implementing new structs or ADRs, always ensure they conform to the fact that:
1.  Friendship has a distinct "establishment" phase (WOT-006).
2.  Data requires an ongoing "sync" phase (WOT-007) capable of operating asynchronously (e.g. over basic sockets).
3.  The schema (WOT-001) must cleanly support delta synchronization (versions/timestamps).

# Security Specification for Firestore Security Rules

## Phase 0: Security Invariants & TDD Spec

### Data Invariants
1. Default Deny: All unmatched paths are strictly denied (`allow read, write: if false`).
2. Authentication Required: Only authenticated users with verified credentials can interact with their user document.
3. User Isolation: A user document at `/users/{userId}` can only be read, created, or updated by the user whose UID matches `{userId}` (`request.auth.uid == userId`).
4. Immutability: The `uid` and `email` fields cannot be altered post-creation.
5. Strict Schema: Fields must strictly conform to allowed keys and sizes (`uid`, `email`, `displayName`, `photoURL`, `role`, `lastLoginAt`, `createdAt`).

### The Dirty Dozen Payloads (Expected to Fail: PERMISSION_DENIED)
1. Unauthenticated read to `/users/{userId}`.
2. Unauthenticated write to `/users/{userId}`.
3. User A attempting to read User B's `/users/{userB}` document.
4. User A attempting to overwrite User B's `/users/{userB}` document.
5. User attempting to create a user document with a mismatched `uid` in the body (`data.uid != request.auth.uid`).
6. User attempting to inject shadow/ghost fields into `/users/{userId}` (e.g. `isAdmin: true` or `secretToken: "xyz"`).
7. User attempting to inject oversized displayName (> 256 chars).
8. User attempting to mutate immutable `uid` on update.
9. Malformed path variable attack (`/users/{oversized_1500_char_string}`).
10. Attempting to write to `/test/connection` (read-only probe).
11. Unauthenticated read to `/test/connection`.
12. Blanket list queries bypassing owner filter without auth.

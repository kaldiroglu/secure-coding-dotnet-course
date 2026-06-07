# Chapter 6 — CWE-639: Insecure Direct Object Reference (IDOR / Missing Object-Level Authorization)

**Time budget:** ~65 min · **CWE:** CWE-639/862/863 · **Files:** `src/Vulnerable/Shop.Api/Controllers/OrdersController.cs` ↔ `src/Fixed/Shop.Api/Controllers/OrdersController.cs` · test `tests/Shop.Tests/AccessControlTests.cs`

## The weakness in one line
The endpoint returns an order by its database ID with no check that the caller owns it, so any authenticated user can read any other user's order by incrementing the ID.

## Live demo script
1. Open the Vulnerable `OrdersController`. Read the `// CWE-639/862` comment aloud — note `db.Orders.Find(id)` with no ownership check whatsoever.
2. Normal call: send `GET /orders/2` with header `X-User-Id: 2` (Bob's own order) → 200, Bob's order data.
3. Fire the exploit: send `GET /orders/1` with header `X-User-Id: 2` (Alice's order, id=1) → **200**, Alice's order returned. Bob read data he has no right to see.
4. Open the Fixed `OrdersController` side-by-side: the controller reads `X-User-Id` from the request, then queries `db.Orders.FirstOrDefault(o => o.Id == id && o.OwnerId == userId)` — the ownership filter is in the query itself. If nothing matches, return `NotFound()` (404), not `Forbidden()` (403).
5. Send the exploit again to the Fixed app (`GET /orders/1`, `X-User-Id: 2`) → **404**. Bob learns nothing about whether order 1 exists or belongs to someone else.
6. Run `dotnet test --filter FullyQualifiedName~AccessControlTests` → green.

## Why it's exploitable (the mechanism)
The application conflates *authentication* (who are you?) with *authorization* (what are you allowed to do?). Once a user is authenticated, the vulnerable endpoint performs no further check before returning the object. Integer IDs are sequential and guessable, so an attacker can enumerate all orders in the system with a simple loop. This class of vulnerability — IDOR — consistently appears in the OWASP API Security Top 10 because authorization checks are easy to forget and hard to detect with static analysis alone.

## The fix (and why it's usually less code)
Scope the database query to the caller's identity: `FirstOrDefault(o => o.Id == id && o.OwnerId == userId)`. This is a single predicate change. The ownership check lives in the query rather than after a fetch, which means unathorised rows are never loaded — efficient and correct. Return 404 (not 403) when the record is not found so that the response does not leak whether the order exists at all.

## The transferable principle
> **Authorize every object access, server-side.**

## "But what about…" — anticipated questions
- **Q:** The test uses an `X-User-Id` header — is that a real auth pattern? **A:** No. `X-User-Id` is a stand-in for a verified identity claim such as a JWT subject (`sub`) that the server has already validated. A raw client-supplied header is trivially spoofable — any caller can write any value they like. In production, extract the user identity from a server-verified token or session, never from a header the client controls.
- **Q:** Why return 404 instead of 403 when Bob asks for Alice's order? **A:** 403 Forbidden tells the attacker "this resource exists, you just can't see it" — that is itself an information leak. 404 Not Found reveals nothing: from Bob's perspective the order simply does not exist. This "resource not found" pattern is the OWASP-recommended response for IDOR.
- **Q:** Shouldn't we fetch the order first and then check ownership, so we can return a more helpful error? **A:** Checking in the query is better: it avoids loading the sensitive object into memory at all, and it is atomic — there is no window between "fetch" and "check" where a race condition could leak data. A post-fetch check is also easy to accidentally omit when the code is refactored later.

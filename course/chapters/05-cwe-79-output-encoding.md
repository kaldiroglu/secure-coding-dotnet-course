# Chapter 5 — CWE-79: Cross-Site Scripting (Stored XSS / Improper Output Encoding)

**Time budget:** ~50 min · **CWE:** CWE-79 · **Files:** `src/Vulnerable/Shop.Api/Controllers/ReviewsController.cs` ↔ `src/Fixed/Shop.Api/Controllers/ReviewsController.cs` · test `tests/Shop.Tests/OutputEncodingTests.cs`

## The weakness in one line
Review bodies are stored verbatim and written into an HTML response without encoding, so a review containing `<script>` markup is delivered to the browser as executable script.

## Live demo script
1. Open the Vulnerable `ReviewsController`. Point to the `Widget` action and read the `// CWE-79` comment aloud — note `$"<li>{r.Body}</li>"` with no encoding call.
2. Post a benign review: `POST /reviews` with `{"productId":1,"author":"Alice","body":"Great product!"}`, then `GET /reviews/widget?productId=1` → normal `<ul><li>Great product!</li></ul>`.
3. Fire the exploit: `POST /reviews` with `{"productId":1,"author":"Mallory","body":"<script>alert(1)</script>"}`. Then `GET /reviews/widget?productId=1` → the raw `<script>` tag appears in the HTML. Open a real browser tab to show the alert firing.
4. Open the Fixed `ReviewsController` side-by-side: `HtmlEncoder.Default.Encode(r.Body)` wraps every body before interpolation. Point out the `using System.Text.Encodings.Web;` import.
5. Send the same XSS payload through the Fixed app → `GET /reviews/widget?productId=1` returns `&lt;script&gt;alert(1)&lt;/script&gt;` — inert text in the browser.
6. Run `dotnet test --filter FullyQualifiedName~OutputEncodingTests` → green.

## Why it's exploitable (the mechanism)
The browser's HTML parser treats everything between `<` and `>` as markup. When untrusted content is written directly into an HTML document, any attacker-supplied tags are parsed as structure rather than text. A `<script>` tag injected this way runs in the context of the page's origin — giving the attacker access to cookies, local storage, and the ability to perform actions as the victim. Because the payload is stored in the database and served to every visitor, this is a *stored* (or *persistent*) XSS, higher severity than reflected XSS.

## The fix (and why it's usually less code)
Call `HtmlEncoder.Default.Encode(value)` before inserting any untrusted string into an HTML context. The encoder converts `<` to `&lt;`, `>` to `&gt;`, `"` to `&quot;`, and so on — characters the browser renders as visible text rather than markup. The data itself is unchanged in the database; the transformation happens only at the output boundary. No input filtering required; the single `Encode` call is the complete fix.

## The transferable principle
> **Encode on output, per context.**

## "But what about…" — anticipated questions
- **Q:** Shouldn't we sanitise (strip tags) when the review is saved rather than at render time? **A:** Encoding on output is safer: you preserve the original data (useful for auditing and future rendering changes) and you can encode correctly for each output context. Input sanitisation is lossy, context-unaware, and often incomplete — stripping `<script>` but missing `<img onerror=…>` is a classic bypass.
- **Q:** Does it matter which encoder we use? **A:** Yes — context is everything. `HtmlEncoder` is correct for HTML text nodes and attribute values. `JavaScriptEncoder` is correct for data written into a `<script>` block. `UrlEncoder` is correct for query-string values. Using the wrong encoder for the context provides no protection.
- **Q:** Our endpoint returns JSON, not HTML — are we safe? **A:** The API is safe in isolation, but not necessarily end-to-end. If a React or Angular front-end later takes the JSON value and uses `innerHTML` or `dangerouslySetInnerHTML` to render it, the XSS fires in the browser. API authors should still encode or, better still, ensure consuming apps use safe DOM APIs (`textContent`, not `innerHTML`).

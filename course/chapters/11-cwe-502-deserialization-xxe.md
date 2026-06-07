# Chapter 11 — CWE-502/611: Unsafe Deserialization and XXE

**Time budget:** ~50 min · **CWE:** CWE-502 / CWE-611 · **Files:** `src/Vulnerable/Shop.Api/Controllers/ImportController.cs` ↔ `src/Fixed/Shop.Api/Controllers/ImportController.cs` · test `tests/Shop.Tests/DeserializationTests.cs`

## The weakness in one line

The import endpoint trusts the payload to name its own .NET type (`TypeNameHandling.All`) and lets the XML parser process DTD external entities — both of which let the caller execute arbitrary code or read server-side files.

## Live demo script

**Demo A — Unsafe JSON Deserialization**

1. Open the Vulnerable `ImportController`. Read the `// CWE-502` comment aloud — point at `TypeNameHandling.All`. Explain: when this flag is set, Newtonsoft.Json reads the `"$type"` field and instantiates whichever .NET class the payload names, including types from any loaded assembly.
2. Show the test payload: it names `ImportGadget` (a domain class in the vulnerable project whose property setter writes a file to disk when set). This is the stand-in for RCE. Send the payload to `POST /import/json` → a sentinel file appears in `%TEMP%`. The server executed code determined entirely by the caller.
3. Open the Fixed `ImportController` side-by-side: `JsonConvert.DeserializeObject<ImportDto>(raw.GetRawText())` — the type is fixed at compile time; `"$type"` is silently ignored. The sentinel file is not created.

**Demo B — XXE (XML External Entity)**

4. Still in the Vulnerable controller, read the `// CWE-611` comment. Note `DtdProcessing = DtdProcessing.Parse` and `XmlResolver = new XmlUrlResolver()` on both the reader settings and the `XmlDocument`. The `async Task<IActionResult>` signature is required by ASP.NET Core 8 which disallows synchronous IO on the request body.
5. Show the test payload: a DTD that declares `&xxe;` as a `SYSTEM` entity pointing at a temp file containing `XXE-SECRET-9999`. Send to `POST /import/xml` → response body contains `"XXE-SECRET-9999"`. Any readable file (SSH keys, app secrets) could be exfiltrated this way.
6. Open the Fixed `ImportController`: `DtdProcessing = DtdProcessing.Prohibit` and `XmlResolver = null` on both objects. The same payload now returns 400 Bad Request. Run `dotnet test --filter FullyQualifiedName~DeserializationTests` → green.

## Why it's exploitable (the mechanism)

`TypeNameHandling.All` delegates object construction to the payload: the deserializer reflectively calls the constructor and setters of whatever type the caller names, including types whose side effects were never intended to be reachable from this code path. Property setters that write files, start processes, or open network connections become remote execution primitives. DTD external entities are a W3C feature designed for document composition; when enabled against untrusted input, they let the parser issue file-system or network requests on the server's behalf, leaking any content the process can read.

## The fix (and why it's usually less code)

For JSON: deserialize into a concrete DTO (`JsonConvert.DeserializeObject<ImportDto>`) at the default Newtonsoft settings (which do not honour `$type`) — the `TypeNameHandling` line and the `JsonSerializerSettings` object are simply removed. For XML: set `DtdProcessing = DtdProcessing.Prohibit` and `XmlResolver = null`; note that these are already the defaults in .NET 8 — the vulnerable code had to actively opt in to the dangerous settings. Both fixes remove configuration lines rather than adding them.

## The transferable principle

> **Never deserialize untrusted data into arbitrary types; disable DTDs.**

## "But what about…" — anticipated questions

- **Q:** Why is `TypeNameHandling` in Newtonsoft.Json dangerous rather than useful? **A:** It was designed for round-tripping polymorphic object graphs in trusted contexts (e.g., internal message queues where both ends are controlled). The danger is that .NET processes load many assemblies; an attacker can name any type in any loaded assembly, and many common framework types have side-effecting constructors or property setters. The Newtonsoft.Json maintainers themselves document it as a security risk and recommend against using it with untrusted input.
- **Q:** Is `BinaryFormatter` the same problem? **A:** Yes, and worse. `BinaryFormatter` has no safe mode — any deserialization of untrusted data is potentially exploitable. Microsoft marked it obsolete in .NET 5, removed it from .NET 7 (throws by default), and fully removed it in .NET 8. If you encounter legacy code using `BinaryFormatter`, migration to `System.Text.Json` or a typed binary format (e.g., `MessagePack` with a known schema) is mandatory.
- **Q:** Why did the vulnerable XML action have to be `async`? **A:** ASP.NET Core 8 disallows synchronous IO on the request body by default (`AllowSynchronousIO = false`). Reading `Request.Body` synchronously throws at runtime. The `async/await` with `StreamReader.ReadToEndAsync()` is the correct pattern, and it is worth noting that this constraint pushed the vulnerable code toward a slightly safer shape regardless of the XML settings.

---
id: ai_security.xxe
title: XML External Entity (XXE) Injection
category: ai_security
vulnerabilityClass: xxe
appliesToStack: applications parsing XML (Java, .NET, PHP, or XML-parser libraries)
requiresAnyTag:
  - java
  - dotnet
  - php
  - xml
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-611"
  - "CWE-827"
  - "CWE-776"
realWorldReferences:
  - title: "OWASP — XML External Entity (XXE) Prevention Cheat Sheet (per-parser hardening for Java/.NET/PHP/etc.)"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
    type: security_blog
  - title: "Facebook XXE — SSRF/file read via a DocuSign SAML/XML endpoint (disclosed bug bounty)"
    url: "https://www.facebook.com/notes/facebook-bug-bounty/xxe-vulnerability/10153077795225589/"
    type: bug_bounty_disclosure
  - title: "PortSwigger Web Security Academy — XXE injection (file disclosure, SSRF, blind/OOB exfiltration)"
    url: "https://portswigger.net/web-security/xxe"
    type: security_blog
  - title: "CVE-2018-1000840 / long tail of XXE CVEs in XML-processing libraries with external entities enabled by default"
    url: "https://cwe.mitre.org/data/definitions/611.html"
    type: vendor_security_advisory
quickModeSummary: >
  Find every place XML is parsed from user-controlled input (request bodies,
  uploaded files, SAML/SOAP messages, SVG/DOCX/XLSX contents, webhooks). XXE
  occurs when the XML parser resolves external entities and/or DTDs, letting an
  attacker define an entity that reads a local file (`file:///etc/passwd`),
  makes a server-side request (SSRF to internal services/cloud metadata), or
  triggers entity-expansion DoS (billion laughs). The defense is
  parser-specific hardening: disable DOCTYPE/DTD processing and external
  entity/parameter-entity resolution (e.g. Java `setFeature(...disallow-
  doctype-decl, true)`, .NET `XmlReaderSettings.DtdProcessing = Prohibit` /
  null resolver, PHP `libxml_disable_entity_loader`/no `LIBXML_NOENT`, lxml
  `resolve_entities=False`, `no_network`). Flag any XML parse of untrusted
  input where external entity/DTD processing is not explicitly disabled —
  many parsers are unsafe by default. Note: JS/Node XML parsers generally do
  not resolve external entities, so XXE is primarily a Java/.NET/PHP/Python
  concern.
fileSelectionHint:
  roles: ["route_handler", "controller", "service", "parser", "upload", "webhook", "saml"]
  matchImports:
    ["javax.xml", "DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory", "System.Xml", "XmlDocument", "XmlReader", "lxml", "xml.etree", "xml.sax", "simplexml_load", "DOMDocument", "libxml"]
  matchAuthMapTags: ["xml", "saml", "soap"]
  maxFiles: 10
  priorityOrder: ["parser", "webhook", "saml", "route_handler", "upload"]
severityHeuristics:
  critical:
    - "An XML parser processing untrusted input has external-entity/DTD resolution enabled (explicitly, or by an unsafe library default that isn't overridden), and the parsed content or entity results are reachable/observable, enabling local file disclosure (secrets, keys, /etc/passwd) or SSRF to internal/metadata endpoints"
    - "A SAML/SSO or signed-XML flow parses assertions with external entities enabled, combining XXE with an authentication-critical path (file read of signing keys, SSRF, or assertion tampering)"
  high:
    - "External entity/DTD processing is enabled on an untrusted XML parse where exfiltration is blind/out-of-band (no direct echo) but an OOB channel (parameter entities to an attacker server) is feasible, still enabling file/SSRF exfiltration"
    - "The parser permits unrestricted entity expansion (no limits), enabling a billion-laughs/quadratic-blowup denial of service from a small malicious document"
  medium:
    - "An XML parser with defaults of unclear safety processes untrusted input and external entities are not explicitly disabled, but exploitability (echo/OOB reachability) is not established — treat as needs-hardening and confirm the parser's default before finalizing severity"
    - "XML is parsed from input that is only partially trusted or requires authentication to reach, with entity processing not disabled"
  low:
    - "XML parsing of genuinely trusted/server-generated input with entity processing not explicitly disabled — latent hardening issue; confirm the input cannot become attacker-influenced before downgrading"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:xml_parser"
  relatedNodeIds: ["component:input_validation", "component:external_system"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:xml_parser"
    to: "component:input_validation"
  - relation: enables
    from: "component:xml_parser"
    to: "component:external_system"
commonAiCodingMistakes:
  - "AI parses untrusted XML with a default parser configuration (`DocumentBuilderFactory.newInstance().newDocumentBuilder()`, `new XmlDocument().Load(...)` on older .NET, PHP `DOMDocument->load` with `LIBXML_NOENT`, lxml with `resolve_entities=True`) without disabling DTD/external-entity processing, not knowing that many of these resolve external entities BY DEFAULT — so the parser is exploitable out of the box."
  - "AI adds `LIBXML_NOENT` (PHP/libxml) believing 'NOENT' means 'no entities' when it actually means 'substitute entities' — turning entity resolution ON — a well-known footgun that enables XXE."
  - "AI hardens the main XML endpoint but forgets that XML also arrives inside other formats: SVG uploads, DOCX/XLSX/ODF (zipped XML), SOAP, SAML assertions, RSS/Atom, and webhook payloads — each parsed by a possibly-unhardened parser."
  - "AI focuses on validating the XML's schema/content but not the parser's entity behavior, so a schema-valid document still carries a malicious DOCTYPE."
  - "AI enables XInclude or a network-capable resolver for a legitimate feature, inadvertently reintroducing external resource fetching (SSRF/file read)."
  - "AI assumes 'we validate uploads by extension', not accounting for an attacker uploading a malicious SVG/XML that passes the extension check and is then parsed server-side."
falsePositiveGuardrails:
  - "Do not flag a parser that explicitly disables DTDs/external entities: Java `setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)` (or disabling external-general-entities/external-parameter-entities and setting XMLConstants.FEATURE_SECURE_PROCESSING), .NET `DtdProcessing = Prohibit`/`XmlResolver = null`, PHP without `LIBXML_NOENT`/`LIBXML_DTDLOAD` (and with `libxml_disable_entity_loader` where applicable), lxml with `resolve_entities=False, no_network=True, load_dtd=False`, defusedxml usage. These are the correct hardened configurations."
  - "Node/JavaScript XML parsers (fast-xml-parser, xml2js, sax-js) do not resolve external entities and are not classic XXE sinks — do not report Node XML parsing as XXE unless a specifically entity-resolving library is in use. (They may still have other issues like entity-expansion DoS in some configs — assess separately.)"
  - "XML parsing of exclusively trusted, server-generated input that no attacker can influence is at most a latent hardening note — establish the input is genuinely untrusted/attacker-reachable before flagging critical/high."
  - "The use of `defusedxml` (Python) or a framework's already-hardened XML handling means the parse is protected — confirm the actual parser/config rather than flagging on the mere presence of XML."
  - "A parser that processes internal-subset entities but has external entity resolution and network access disabled is not exploitable for file/SSRF — distinguish internal entity substitution from EXTERNAL entity resolution."
---

## Root Cause Explanation

XML is not just a data format — the XML specification includes Document Type
Definitions (DTDs) and *entities*, including *external* entities that instruct
the parser to fetch and inline content from a URI. When a parser resolves
those external entities on attacker-controlled input, the attacker gains a
primitive to make the *server* read files (`file:///etc/passwd`, application
secrets, cloud credentials), make requests to internal services or the cloud
metadata endpoint (SSRF), or expand nested entities into gigabytes of memory
(billion-laughs DoS). The vulnerability is a parser *configuration* issue, and
the trap that makes it pervasive is that many mature XML parsers — especially
in Java, .NET, PHP, and Python — resolve external entities *by default*.

AI-generated code walks straight into this because the default, minimal way to
parse XML is the unsafe way. `DocumentBuilderFactory.newInstance()`,
`XmlDocument.Load` on older .NET, `DOMDocument->load` with `LIBXML_NOENT`, lxml
with default resolution — all parse a malicious `<!DOCTYPE>` without complaint.
Worse, the hardening is parser-specific and non-obvious: there's no single
"safe mode" flag, and at least one option (PHP's `LIBXML_NOENT`) is named so
misleadingly that developers enable XXE while believing they're disabling it.

The reach of the bug is wider than "an XML API," which is where AI hardening
tends to stop. XML rides inside SVG images, Office documents (DOCX/XLSX are
zipped XML), SOAP, SAML/SSO assertions, RSS/Atom feeds, and webhooks — each
parsed somewhere, often by an unhardened parser, often from an upload that
passed only an extension check. The defense is uniform in intent even though
its syntax varies: on every parse of untrusted XML, explicitly disable DOCTYPE/
DTD processing and external (general and parameter) entity resolution, disable
network access, and cap entity expansion. Note the one major exception:
JavaScript/Node XML parsers generally do not resolve external entities, so
classic XXE is primarily a Java/.NET/PHP/Python concern.

## Vulnerable Patterns

```java
// Java — default factory resolves external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
Document doc = dbf.newDocumentBuilder().parse(userXmlStream); // XXE
```

```csharp
// .NET (older/misconfigured) — DTD processing / resolver enabled
var doc = new XmlDocument();          // pre-4.5.2 defaults, or DtdProcessing=Parse
doc.Load(userXmlStream);
```

```php
// PHP — LIBXML_NOENT actually turns entity substitution ON
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);   // XXE enabled
```

Malicious document:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<r>&x;</r>
```

Correct shapes disable DTDs/external entities before parsing:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setXIncludeAware(false); dbf.setExpandEntityReferences(false);
```

```csharp
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
using var reader = XmlReader.Create(userXmlStream, settings);
```

## Data Flow Tracing Guide

1. Enumerate every XML parse: DOM/SAX/StAX builders (Java), `XmlDocument`/
   `XmlReader`/`XDocument` (.NET), `DOMDocument`/`simplexml_load_*`/`XMLReader`
   (PHP), `lxml`/`xml.etree`/`xml.sax` (Python), and any SAML/SOAP/feed/office/
   SVG parsing.
2. For each, determine whether the input is untrusted (request body, upload,
   webhook, SAML assertion) or server-trusted.
3. For untrusted parses, inspect the parser configuration: are DTDs/external
   entities explicitly disabled? Identify the library default if not
   overridden (many default to unsafe).
4. Assess exfiltration reachability: is parsed content echoed (direct XXE), or
   is only OOB feasible (blind)? Is entity expansion capped?
5. For the non-obvious carriers (SVG/DOCX/SAML/SOAP), confirm which parser
   handles them and its config.

## Evidence Checklist

- [ ] The XML parse call site quoted, with the parser/factory and its
      configuration (or lack of hardening) shown.
- [ ] The untrusted origin of the parsed XML, traced from the request/upload.
- [ ] A statement of the library's default entity behavior when hardening is
      absent (to establish exploitability).
- [ ] The impact channel (file read / SSRF / DoS) and whether it's direct or
      blind/OOB.
- [ ] A concrete DOCTYPE/entity payload the traced path would process.

A finding must establish untrusted input reaching a parser whose external-
entity/DTD processing is not disabled; a hardened parser is not a finding.

## Attack Scenario Template

> An attacker submits [XML body / SVG or Office upload / SAML assertion /
> webhook] containing a DOCTYPE with an external entity pointing at
> [file:///... or an internal/metadata URL]. Because [file:line] parses it
> with [parser] whose external-entity/DTD processing is [enabled explicitly /
> left at an unsafe default], the server [reads the local file and returns/
> exfiltrates it / issues a request to the internal service or metadata
> endpoint / expands entities into a DoS], resulting in [disclosure of
> secrets/credentials / SSRF into internal systems / denial of service].

## Graph Mapping Instructions

- Ensure a `component:xml_parser` node exists, with a `depends_on` edge to
  `component:input_validation`.
- File-read/SSRF XXE findings add an `enables` edge from the finding node to
  `component:external_system` (or a file-system/metadata node if the schema
  supports one) and should note the SSRF/file-read class in `reasoning`.
- Each concrete XXE sink is a `finding:<uuid>` vulnerability node with a
  `causes` edge from `component:xml_parser`.

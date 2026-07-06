---
id: technology.java_spring.security
title: "Java / Spring: Spring Security, JPA & Deserialization"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: java
requiresAnyTag: ["java"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-285"
  - "CWE-89"
  - "CWE-502"
realWorldReferences:
  - title: "Spring4Shell — remote code execution via data binding on Spring Framework (CVE-2022-22965)"
    url: "https://spring.io/security/cve-2022-22965"
    type: vendor_security_advisory
  - title: "Spring Security — broken access control via mismatched authorization rules / method-security misconfiguration (CVE-2023-34035)"
    url: "https://spring.io/security/cve-2023-34035"
    type: vendor_security_advisory
  - title: "Equifax 2017 breach — Apache Struts RCE via unpatched CVE-2017-5638 (US GAO report)"
    url: "https://www.gao.gov/products/gao-18-559"
    type: incident_postmortem
  - title: "OWASP — Deserialization of Untrusted Data and the Java gadget-chain problem"
    url: "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
    type: security_blog
quickModeSummary: >
  Review Spring Security configuration and controllers together. The dominant
  risks: authorization rules in SecurityFilterChain that don't match actual
  endpoints (a `/admin/**` rule that misses `/admin/api/...`, or
  antMatcher/mvcMatcher path-matching mismatches that let requests slip past),
  method-level `@PreAuthorize` missing on service methods reached by multiple
  paths, and IDOR where a controller loads an entity by id without an
  ownership/authority check. Also check JPA/JDBC for string-concatenated JPQL/
  SQL (injection) instead of parameterized queries or `@Param` bindings,
  native Java deserialization of untrusted input (`ObjectInputStream`,
  unsafe Jackson polymorphic typing), SpEL/expression evaluation on user
  input, and CSRF protection being disabled globally on a cookie-session app.
fileSelectionHint:
  roles: ["controller", "config", "service", "repository", "filter", "security"]
  matchImports:
    ["org.springframework.security", "org.springframework.web.bind.annotation", "javax.persistence", "jakarta.persistence", "org.springframework.data.jpa", "com.fasterxml.jackson", "java.io.ObjectInputStream"]
  matchAuthMapTags: ["java", "spring", "jwt"]
  maxFiles: 14
  priorityOrder: ["security", "config", "controller", "repository"]
severityHeuristics:
  critical:
    - "Native Java deserialization of untrusted input (ObjectInputStream.readObject on request data) or Jackson polymorphic deserialization with default typing enabled, reachable from user input — a gadget-chain RCE surface (Spring4Shell / Struts class)"
    - "An authorization rule in the SecurityFilterChain fails to cover a sensitive endpoint (path-pattern mismatch, wrong matcher, ordering that permits before it denies), leaving it accessible without the intended role"
    - "User input concatenated into JPQL/HQL/native SQL (createQuery/createNativeQuery with string building) enabling SQL/JPQL injection"
  high:
    - "A controller/service loads an entity by id and returns/mutates it without verifying the principal's ownership/authority (IDOR), or @PreAuthorize/@PostAuthorize is missing on a privileged service method"
    - "User input is evaluated as a SpEL expression, or CSRF protection is disabled (`csrf().disable()`) on an application using cookie/session authentication"
  medium:
    - "Authorization is present but relies on request-supplied identifiers (a userId in the body/path used to scope data instead of the authenticated principal), or actuator endpoints are exposed without authentication"
    - "Mass-assignment via direct entity binding (`@ModelAttribute`/binding request params straight onto a JPA entity) without a DTO or field allow-list"
  low:
    - "Security headers not configured, verbose error pages/stack traces exposed, or a permissive CORS configuration (allowedOrigins '*') on authenticated endpoints"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:authentication", "component:api_layer", "component:database_access"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:api_layer"
  - relation: depends_on
    from: "component:api_layer"
    to: "component:database_access"
commonAiCodingMistakes:
  - "AI writes a SecurityFilterChain rule like `.requestMatchers(\"/admin/**\").hasRole(\"ADMIN\")` but the sensitive endpoint is actually `/api/admin/...` or is served under a different context path, so the rule never matches and the endpoint is open — path-pattern mismatches are the most common Spring access-control bug."
  - "AI relies on URL-based authorization alone and omits method-level `@PreAuthorize` on service methods, so a service reachable from a second controller path (or internally) bypasses the URL rule entirely."
  - "AI builds a JPA query with `em.createQuery(\"FROM User WHERE email = '\" + email + \"'\")` string concatenation instead of a parameterized `:email` bind, reintroducing injection under an ORM."
  - "AI deserializes untrusted input with `ObjectInputStream` or enables Jackson default typing (`enableDefaultTyping`) for 'flexibility,' opening a gadget-chain RCE surface (the Spring4Shell/Struts lineage)."
  - "AI calls `http.csrf().disable()` to 'make the API work' on a cookie/session-authenticated app, removing CSRF protection from state-changing endpoints."
  - "AI binds request parameters directly onto a JPA entity (`@ModelAttribute User user`) enabling mass-assignment of fields like `role`/`enabled` the user shouldn't control — Spring4Shell itself was a data-binding flaw."
falsePositiveGuardrails:
  - "Do not flag a SecurityFilterChain as broken without confirming the actual endpoint path against the matcher: if the matcher pattern genuinely covers the endpoint (including context path and matcher type), the rule is effective. Trace the real request path."
  - "A method annotated with an effective `@PreAuthorize`/`@Secured` that checks the specific authority, plus URL rules, is defense-in-depth and correct — do not flag method security as missing when it's present and enforced (global method security enabled)."
  - "JPA queries using `:named` or positional bind parameters with `setParameter`/`@Param` are parameterized and safe — only string concatenation into the query is injection."
  - "CSRF disabled on a purely stateless, token-authenticated API (no cookies/session used for auth) is an accepted pattern — confirm the app doesn't authenticate via cookies before flagging."
  - "Jackson without default typing, deserializing into concrete DTO types, is not the unsafe-polymorphic-deserialization case — confirm default typing / ObjectInputStream on untrusted data before flagging RCE."
---

## Root Cause Explanation

Spring Security is powerful but its authorization model has two layers —
URL-based rules in the `SecurityFilterChain` and method-based rules
(`@PreAuthorize`/`@Secured`) — and getting security right means both matching
the *right paths* and not relying on URL rules alone. The recurring
AI-generated failure is a path-pattern mismatch: a rule guards `/admin/**`
while the sensitive controller is mapped under `/api/admin` or a different
context path, so the rule silently never matches and the endpoint ships open.
CVE-2023-34035 was exactly this class — mismatched authorization rules
letting requests through. Because Spring's matchers (`requestMatchers`,
antMatcher vs. mvcMatcher) have subtle path-resolution differences, these
mismatches are easy to introduce and hard to see.

The second Spring-specific danger is deserialization and data binding. Java's
native serialization plus a classpath full of libraries yields gadget chains
that turn `ObjectInputStream.readObject` on attacker data into remote code
execution; Jackson's polymorphic "default typing" opens the same door. And
Spring's own data binding — mapping request parameters onto objects — was the
Spring4Shell RCE (CVE-2022-22965). AI reaches for these "flexible" mechanisms
without registering that they execute attacker-influenced code paths.

The remaining surface is familiar: JPQL/SQL built by string concatenation
instead of bind parameters, IDOR from unowned entity ids, SpEL evaluation on
user input, CSRF disabled on cookie-session apps, and exposed actuator
endpoints.

## Vulnerable Patterns

```java
// Path-pattern mismatch — rule never matches the real endpoint
http.authorizeHttpRequests(a -> a
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated());
// but the controller is @RequestMapping("/api/admin") → not covered by /admin/**
```

```java
// JPQL injection
em.createQuery("SELECT u FROM User u WHERE u.email = '" + email + "'");

// Untrusted deserialization → gadget-chain RCE
Object o = new ObjectInputStream(request.getInputStream()).readObject();
```

```java
http.csrf(csrf -> csrf.disable()); // on a cookie/session-authenticated app
```

Correct shapes match real paths, add method security, bind parameters, and
avoid native deserialization:

```java
http.authorizeHttpRequests(a -> a
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated());

@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long id) { /* ... */ }

em.createQuery("SELECT u FROM User u WHERE u.email = :email")
  .setParameter("email", email);
```

## Data Flow Tracing Guide

1. Read the SecurityFilterChain and list every authorization rule with its
   matcher and pattern. For each controller mapping, resolve the actual path
   (including context path) and confirm a rule covers it with the intended
   authority. Flag any sensitive mapping no rule covers.
2. Check for method security (`@EnableMethodSecurity`, `@PreAuthorize`) on
   privileged service methods reachable by multiple paths.
3. Grep for `createQuery`/`createNativeQuery`/JDBC with string concatenation
   vs. bind parameters.
4. Search for `ObjectInputStream`, Jackson `enableDefaultTyping`/
   `activateDefaultTyping`, and SpEL `ExpressionParser` fed by user input.
5. Check `csrf().disable()` against whether auth uses cookies/session; check
   actuator exposure and CORS config.

## Evidence Checklist

- [ ] The SecurityFilterChain rule(s) and the actual controller path they're
      claimed to cover, showing the match or mismatch.
- [ ] For injection/deserialization: the sink and the user-controlled origin.
- [ ] For IDOR: the entity load and the ownership/authority check status.
- [ ] The authentication model (cookie/session vs. token) where CSRF is
      disabled.

## Attack Scenario Template

> An attacker sends [method] [real endpoint path] [with untrusted serialized
> data / a SQL payload / another user's entity id]. Because [file:line] [the
> authorization rule's pattern does not match this path / deserializes
> untrusted input / concatenates input into JPQL / omits the ownership
> check], the request [reaches the endpoint without the required role /
> triggers gadget-chain code execution / injects into the query / accesses
> another user's entity], resulting in [impact].

## Graph Mapping Instructions

- Ensure `component:authorization` exists with a `protects` edge to
  `component:api_layer`.
- Deserialization/RCE findings should add a `causes` edge from the finding
  node toward a code-execution component if the graph schema supports one.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from its root-cause component (authorization, database_access, or
  input_validation). Link shared root causes in `reasoning`.

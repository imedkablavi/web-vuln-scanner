# API insertion points, Postman, and WSDL import

This document describes the current API attack-surface model. It intentionally separates discovery from active mutation so that importing a collection or service definition does not silently replay captured or state-changing requests.

## Canonical insertion paths

`InputField` can carry a canonical `path` in addition to its display `name` and location (`query`, `body`, `path`, `header`, or `cookie`). JSON request bodies use RFC 6901-style pointers.

Examples:

- `/profile/email`
- `/owner/id`
- `/reviewer/id`
- `/items/0/id`

This means two leaf fields named `id` are no longer treated as the same insertion point.

The site map persists only structural metadata such as name, location, canonical path, data type, and required state. It does not persist the original request value.

## Canonical request materialization

`core.request_materializer` builds the transport shape for an `AttackSurface` without performing network I/O. It preserves query parameters on non-GET methods, preserves false/zero values, reconstructs nested JSON from canonical pointers, and can mutate exactly one selected JSON pointer.

Plugin candidate requests use this materializer instead of maintaining a second body/query reconstruction implementation.

Nested JSON remains gated in the stable active plugins until the scanner baseline path is switched to the same materializer. This prevents response comparisons where the baseline is flat but the candidate is nested.

## OpenAPI

OpenAPI request-body discovery recursively models:

- nested object properties;
- array item properties;
- local `#/...` references;
- `allOf` components;
- required fields;
- primitive data types.

The parser is bounded by schema depth and maximum insertion-point limits.

OpenAPI 3 server resolution also handles the default `/` server, path/operation server overrides, server-variable defaults, and scope rejection for external servers.

JSON body paths are retained as canonical pointers. Flat form and multipart fields retain their form field name because their wire representation is not a nested JSON document.

## Postman Collection v2.x JSON

`web-vuln-postman` imports a Postman Collection v2.x JSON document into a sanitized attack-surface inventory.

Example:

```text
web-vuln-postman collection.json \
  --target https://staging.example \
  --output postman-inventory.json
```

The importer:

- never replays collection requests;
- enforces the explicit authorized target scope;
- pins common base-URL variables to the authorized target instead of trusting collection values;
- removes query values while retaining query names;
- does not copy Authorization, Cookie, API-key, or authentication-token values;
- replaces imported body values with type-compatible scanner samples;
- extracts nested JSON insertion paths;
- skips multipart file values;
- inventories GraphQL variables without making them active targets;
- keeps DELETE inactive even when active eligibility is explicitly requested.

State-changing Postman methods are not active-eligible by default.

## WSDL 1.1 / SOAP inventory

`web-vuln-wsdl` imports a local WSDL 1.1 file into a sanitized SOAP attack-surface inventory.

Example:

```text
web-vuln-wsdl service.wsdl \
  --target https://staging.example \
  --output wsdl-inventory.json
```

The importer:

- parses the WSDL locally and performs no service-operation replay;
- rejects WSDL input containing DTD or ENTITY declarations;
- enforces the explicit authorized target scope on SOAP service addresses;
- inventories services, ports, bindings, operations, SOAPAction metadata, and SOAP 1.1/1.2 content types;
- expands local XSD complex types into bounded canonical XML-style insertion paths;
- keeps every SOAP surface `active_eligible: false` in the current release.

This is discovery/inventory support, not an active SOAP vulnerability scanner. Active XML/SOAP mutation requires a separate request-envelope materializer and verification model before it can be promoted safely.

## Active mutation safety

The request mutation layer can reconstruct and mutate a selected nested JSON pointer without changing same-named fields elsewhere in the body.

Stable plugins do **not** automatically attack nested JSON paths until the scanner baseline request path is proven to consume the same canonical materializer. This is deliberate: a candidate request and its baseline must be structurally equivalent except for the selected mutation, otherwise response differences could become false positives.

Top-level inputs continue to use the existing stable active checks. Nested JSON and WSDL/XSD paths are inventory-visible immediately.

## Current format scope

Postman Collection v2.x JSON is supported. Postman's current 3.0 collection format is multi-file/YAML based and will be implemented as a separate adapter over the same internal insertion-point model rather than by duplicating scanner logic.

WSDL 1.1 SOAP inventory import is implemented. WSDL 2.0 and active SOAP mutation are not claimed as supported.

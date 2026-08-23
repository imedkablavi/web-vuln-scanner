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

Both scanner baselines and plugin candidate requests consume the same materializer. This removes the earlier flat-baseline/nested-candidate mismatch and makes response comparisons structurally comparable: method, untouched query values, untouched body fields, headers, cookies, and JSON shape remain aligned except for the selected mutation.

The regression suite covers duplicate nested leaf names and verifies that `/owner/id` and `/reviewer/id` are independently targetable. The authorized local smoke suite additionally verifies the same behavior over a real HTTP socket, including preservation of a POST query parameter and a boolean `false` value.

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

## Active nested JSON checks

Stable SQL injection and reflected-markup checks can target canonical nested JSON body paths when the surface is explicitly modeled as JSON (`application/json`, a `+json` media type, or `body_format: json`).

For example, two fields named `id` at `/owner/id` and `/reviewer/id` generate distinct test cases and distinct differential-cache identities. Mutating one path does not mutate the other.

Nested XML and form-encoded inputs do not inherit JSON-pointer behavior. They remain inactive unless their own wire-format materializer and verification contract supports them. This prevents a discovered structural path from being mistaken for a safely replayable active input.

`active_eligible: false` is enforced centrally by `ScannerEngine` before baseline generation, so inventory-only surfaces cause no active baseline or plugin traffic.

## Postman Collection v2.x JSON

`web-vuln-postman` imports a Postman Collection v2.x JSON document into a sanitized attack-surface inventory.

Example:

```text
web-vuln-postman collection.json \
  --target https://staging.example \
  --output postman-inventory.json
```

The importer:

- never replays collection requests during import;
- enforces the explicit authorized target scope;
- pins common base-URL variables to the authorized target instead of trusting collection values;
- removes query values while retaining query names;
- does not copy Authorization, Cookie, API-key, or authentication-token values;
- replaces imported body values with type-compatible scanner samples;
- extracts nested JSON insertion paths;
- skips multipart file values;
- inventories GraphQL variables without making them active targets;
- keeps DELETE inactive even when active eligibility is explicitly requested.

State-changing Postman methods are not active-eligible by default. Imported inventory can be merged into the main scan/site-map flow without bypassing the central active-eligibility guard.

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

## Current format scope

Postman Collection v2.x JSON is supported. Postman's current 3.0 format uses multiple YAML files such as `*.request.yaml`; a separate adapter is being designed over the same internal insertion-point model rather than by duplicating scanner logic.

WSDL 1.1 SOAP inventory import is implemented. WSDL 2.0 and active SOAP mutation are not claimed as supported.

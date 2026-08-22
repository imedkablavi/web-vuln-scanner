# API insertion points and Postman import

This document describes the current API attack-surface model. It intentionally separates discovery from active mutation so that importing a collection does not silently replay captured or state-changing requests.

## Canonical insertion paths

`InputField` can carry a canonical `path` in addition to its display `name` and location (`query`, `body`, `path`, `header`, or `cookie`). JSON request bodies use RFC 6901-style pointers.

Examples:

- `/profile/email`
- `/owner/id`
- `/reviewer/id`
- `/items/0/id`

This means two leaf fields named `id` are no longer treated as the same insertion point.

The site map persists only structural metadata such as name, location, canonical path, data type, and required state. It does not persist the original request value.

## OpenAPI

OpenAPI request-body discovery recursively models:

- nested object properties;
- array item properties;
- local `#/...` references;
- `allOf` components;
- required fields;
- primitive data types.

The parser is bounded by schema depth and maximum insertion-point limits.

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

## Active mutation safety

The request mutation layer can reconstruct and mutate a selected nested JSON pointer without changing same-named fields elsewhere in the body.

However, stable plugins do **not** automatically attack nested JSON paths until the baseline request path is proven to reconstruct the same document. This is deliberate: a candidate request and its baseline must be structurally equivalent except for the selected mutation, otherwise response differences could become false positives.

Top-level inputs continue to use the existing stable active checks. Nested paths are inventory-visible immediately.

## Current format scope

Postman Collection v2.x JSON is the first supported Postman import format. Postman's newer 3.0 collection format is multi-file/YAML based and will be implemented as a separate adapter over the same internal insertion-point model rather than by duplicating scanner logic.

SOAP/WSDL import is also planned as an adapter over this model. It is not claimed as implemented by this document.

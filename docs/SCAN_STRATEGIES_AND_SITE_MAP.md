# Scan strategies and application site map

Web Vulnerability Scanner separates **safety authorization** from **coverage depth**.

- A **profile** decides which kinds of actions are allowed: `passive`, `safe-active`, or `full-authorized`.
- A **strategy** decides how much of the authorized application is mapped and, when a profile already permits active checks, how much authorized test volume is available: `lightweight`, `balanced`, or `deep`.

This distinction prevents a high-coverage scan from silently enabling a more dangerous class of checks.

## Examples

Fast passive inventory:

```bash
web-vuln-scanner scan https://app.example \
  --profile passive \
  --strategy lightweight
```

Default routine assessment:

```bash
web-vuln-scanner scan https://app.example \
  --profile safe-active \
  --strategy balanced
```

Broad authorized assessment:

```bash
web-vuln-scanner scan https://staging.example \
  --profile full-authorized \
  --strategy deep \
  --config scanner.yaml
```

List the installed strategy descriptions:

```bash
web-vuln-scanner strategies
web-vuln-scanner strategies --json
```

The profile materializer supports the same model:

```bash
web-vuln-profile safe-active \
  --strategy deep \
  --config config/default_config.yaml \
  --output safe-active-deep.yaml
```

## Strategy behavior

| Strategy | HTTP crawl | Sitemap | Static JS | Browser budget | Intended use |
| --- | ---: | ---: | ---: | ---: | --- |
| `lightweight` | 250 URLs / depth 1 | 100 URLs | 4 scripts / 50 endpoints | 8 pages | quick feedback |
| `balanced` | 2,000 URLs / depth 3 | 500 URLs | 10 scripts / 100 endpoints | 20 pages | routine assessment |
| `deep` | 10,000 URLs / depth 5 | 5,000 URLs | 50 scripts / 1,000 endpoints | 100 pages | broad authorized mapping |

`deep` also raises the overall scan deadline and expands request budgets **only for checks already enabled by the selected profile**. It does not enable opt-in or experimental checks.

For example:

- `passive + deep` still sends no active vulnerability payloads;
- `safe-active + deep` increases the number of surfaces covered by the already-approved safe-active checks;
- `full-authorized + deep` can increase bounded browser verification coverage;
- LFI/path traversal and command injection remain disabled by release maturity policy in every built-in profile.

## Site map

The HTTP crawler writes a secret-minimized application map to the configured report directory. The default file is:

```text
reports/site_map.json
```

The map records:

- normalized URL without query values or fragments;
- host and path;
- observed/discovered HTTP methods;
- discovery provenance such as crawler response, HTML link, form, JavaScript, HAR, robots.txt, or sitemap;
- whether the URL was actually requested or only discovered;
- minimum observed crawl depth;
- actor IDs when applicable;
- input point **names and locations** (`query`, `body`, `header`, `cookie`, and similar model locations);
- related attack-surface fingerprints.

It deliberately does **not** persist original query values, form values, authentication tokens, or other captured parameter values.

Authenticated crawler maps use an actor-specific suffix so one actor's map does not overwrite another actor's file.

## Discovery sources

### HTML

The crawler maps links, frames, meta refreshes, GET forms, and POST forms. It models named `input`, `textarea`, and `select` controls. File inputs and submit/button controls are not turned into attack inputs.

A document `<base href>` is honored for link and form resolution.

### JavaScript

Static JavaScript discovery remains inventory-first. Literal same-scope endpoints are collected, but inferred state-changing methods are not sent merely because a route string appears in JavaScript.

### `robots.txt`

The scanner can use concrete `Allow` and `Disallow` paths as discovery hints and can discover sitemap locations from `Sitemap:` directives.

`robots.txt` is **not** treated as authorization. Scan authorization still comes from the configured target/scope and the operator's permission to test it.

Wildcard robot rules are kept out of the request queue because they are patterns rather than concrete URLs.

### `sitemap.xml`

The crawler supports normal sitemap URL sets and bounded sitemap-index recursion. Sitemap files and discovered URLs remain subject to normal scope checks and size/count budgets.

Malformed, oversized, or unavailable optional sitemap/robots resources are recorded as discovery diagnostics; they do not by themselves downgrade an otherwise complete scan to `partial`.

### HAR

HAR seeding remains sanitized discovery input. Captured authentication material and state-changing requests are not replayed simply because they appeared in a HAR.

## Configuration

```yaml
scanner:
  strategy: balanced

  crawler:
    discovery_files:
      robots_txt: true
      sitemap_xml: true
      max_sitemap_urls: 500
      max_sitemap_files: 10
      max_file_bytes: 2097152

    site_map:
      enabled: true
      output_file: site_map.json
      max_entries: 5000
```

The configured target is requested before optional robots/sitemap-derived crawl seeds can consume the normal crawler URL budget.

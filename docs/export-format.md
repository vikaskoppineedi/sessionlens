# Export format (`sessionlens-export/1`)

Every capture writes `<captures>/<session-id>/export/`:

```
export/
  README.md          short field guide (for whoever, or whatever, reads the export)
  session.json       the timeline
  screenshots/       step-NN.jpg, referenced from steps[].screenshot
  bodies/            request/response bodies over 64 KB, referenced from body.file
```

Rebuild it any time with `python -m sessionlens export <session-id>`, or download it as a zip from
the analyzer.

## `session.json`

```jsonc
{
  "format": "sessionlens-export/1",
  "session": {
    "id": "20260101-120000",
    "startedAt": "2026-01-01T12:00:00.000Z",
    "durationMs": 48326,
    "userAgent": "Mozilla/5.0 (Macintosh; ...) Chrome/155.0.0.0 Safari/537.36"
  },
  "steps": [
    {
      "step": 4,
      "kind": "action",                    // start | action | nav | spa
      "label": "click \"9 killed in Pennsylvania shooting…\"",
      "atMs": 17100,                       // ms since session start
      "time": "2026-01-01T12:00:17.100Z",
      "action": { "type": "click", "selector": "div#stream > ul > li:nth-of-type(3) > a", "text": "…" },
      "pageUrl": "https://www.yahoo.com/news/articles/…",
      "screenshot": "screenshots/step-04.jpg",
      "requests": [
        {
          "id": "r0412",
          "atMs": 17140,
          "method": "GET",
          "url": "https://www.yahoo.com/news/articles/…",
          "type": "main_frame",            // Chrome resource type
          "status": 200,
          "redirectTo": null,
          "protocol": "h2",                // h1 | h2 | h3 (null if only the extension saw it)
          "initiator": "https://www.yahoo.com",
          "fromCache": false,
          "error": null,
          "query": [["ncid", "…"]],
          "requestHeaders": [["cookie", "A1=…; A3=…"], ["user-agent", "…"]],
          "requestBody": { "kind": "none", "size": 0 },
          "responseHeaders": [["set-cookie", "…"], ["content-type", "text/html; charset=utf-8"]],
          "responseBody": { "kind": "text", "size": 812345, "contentType": "text/html", "file": "bodies/r0412-response.html" },
          "cookiesSent": [".yahoo.com A1", ".yahoo.com A3"],
          "cookiesSet": [
            { "cookie": ".yahoo.com cmp", "outcome": "stored" },
            { "cookie": "ads.example tuid", "outcome": "blocked", "reason": "Third-party context: Chrome blocks third-party cookies by default" }
          ]
        }
      ],
      "cookieChanges": [
        {
          "cookie": ".yahoo.com cmp",
          "change": "changed",             // added | changed | removed
          "before": "t=1791679700&j=0",
          "after": "t=1791679717&j=0",
          "attributes": { "httpOnly": false, "secure": true, "sameSite": "no_restriction", "session": false, "hostOnly": false, "expirationDate": 1825886717 },
          "setBy": { "source": "header", "request": "r0412" }   // header | javascript | browser
        }
      ],
      "storageChanges": [
        { "area": "localStorage", "origin": "https://www.yahoo.com", "key": "…", "change": "added", "before": null, "after": "…" }
      ],
      "disk": [
        { "kind": "cache", "label": "Cache entries", "items": [{ "url": "https://s.yimg.com/…", "size": 48211 }] }
      ]
    }
  ],
  "finalState": {
    "cookies": [{ "domain": ".yahoo.com", "name": "A1", "path": "/", "value": "…", "attributes": { } }],
    "localStorage": { "https://www.yahoo.com": { "key": "value" } },
    "sessionStorage": { "https://www.yahoo.com#tab1": { "key": "value" } }
  }
}
```

## Rules

- **Only the capture browser.** A request is included only if Chrome reported it to the SessionLens
  extension. Traffic from other apps and Chrome's own background services is dropped.
- **Exact bytes when possible.** Headers come from the decrypted network capture; if the network
  copy is missing (e.g. served from cache), the extension's view is used.
- **Bodies are decoded.** gzip / br / zstd are undone. `kind` is `form`, `json`, `text`, `binary`,
  `none`, `skipped` or `unavailable`. Text/JSON over 64 KB goes to `bodies/`. Scripts and stylesheets
  are recorded by size only (`skipped`); images, fonts and media by size and type (`binary`).
- **Cookie keys** are `"<domain> <name>"` (plus the path if it isn't `/`). A leading dot in the
  domain means the cookie is also sent to subdomains.
- **Cross-references.** `setBy.request` / `removedBy.request` point at a request `id`; screenshots are
  named by step.
- **Masking.** Password fields, security-question answers and one-time codes are replaced with
  `••••••`. Cookie values and tokens are real.

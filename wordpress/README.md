# WordPress vulnerabilities

WordPress findings, split by component type. See the [root index](../README.md) for the cross-ecosystem master table.

## Plugins

| CVE                   | Name                                                                                                                                                            | Plugin                                                                      | Slug           | Type                           | Severity     |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | -------------- | ------------------------------ | ------------ |
| CVE-2026-12089        | [WS Optimize – All-in-One Speed Booster & Cache Tools <= 3.3.19 - Authenticated (Editor+) Arbitrary File Read](./plugins/lws-optimize/CVE-2026-12089/README.md) | WS Optimize – All-in-One Speed Booster & Cache Tools                        | `lws-optimize` | Arbitrary File Read            | Medium (4.9) |
| CVE-2026-16042        | [LWS Optimize < 3.4 - Subscriber+ Cache Deletion](./plugins/lws-optimize/CVE-2026-16042/README.md)                                                              | WS Optimize – All-in-One Speed Booster & Cache Tools                        | `lws-optimize` | Broken Access Control          | Medium (4.3) |
| CVE-2026-16297        | [Clearfy < 2.4.3 - Admin+ PHP Object Injection via Settings Import](./plugins/clearfy/CVE-2026-16297/README.md)                                                 | Clearfy Cache – WordPress optimization plugin, Minify HTML, CSS & JS, Defer | `clearfy`      | Insecure Deserialization       | Medium (4.1) |
| CVE-2026-14331        | [Subscribe2 < 10.46 - Reflected XSS via email Parameter](./plugins/subscribe2/CVE-2026-14331/README.md)                                                         | Subscribe2 – Form, Email Subscribers & Newsletters                          | `subscribe2`   | Reflected Cross-Site Scripting | Medium (4.7) |
| Dup of CVE-2026-16296 | [Clearfy < 2.4.3 - Open Redirect via Cyrlitera 404 Handler](./plugins/clearfy/open-redirect-via-cyrlitera-component/README.md)                                  | Clearfy Cache – WordPress optimization plugin, Minify HTML, CSS & JS, Defer | `clearfy`      | Open Redirect                  | Medium (4.7) |


## Themes

| CVE        | Name | Theme | Slug | Type | Severity |
| ---------- | ---- | ----- | ---- | ---- | -------- |
| *none yet* |      |       |      |      |          |



## Core

| CVE        | Name | Component | Type | Severity |
| ---------- | ---- | --------- | ---- | -------- |
| *none yet* |      |           |      |          |


## Layout

```
wordpress/
├── README.md                      # this file
├── plugins/
│   └── <plugin-slug>/             # canonical wordpress.org slug
│       └── <cve>/
│           ├── README.md
│           ├── poc.py
│           └── screenshots/
├── themes/
│   └── <theme-slug>/
│       └── <cve>/
└── core/
    └── <cve>/             # no slug level — core is a single component
```

## Notes

- **Slugs** use the canonical `wordpress.org` plugin/theme slug (the value in the plugin's directory URL, e.g. `wordpress.org/plugins/contact-form-x/`), which is globally unique.
- **Core findings** are one level shallower than plugins/themes: there is no slug layer, since core is a single component.
- WordPress CVEs are most often assigned by **Patchstack**, **Wordfence**, or **WPScan** acting as CNAs — the assigning authority is noted in each finding's README.
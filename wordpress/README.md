# WordPress vulnerabilities

WordPress findings, split by component type. See the [root index](../README.md) for the cross-ecosystem master table.

## Plugins

| CVE            | Name                                                                                                                                                            | Plugin                                               | Slug           | Type                | Severity     |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------- | ------------------- | ------------ |
| CVE-2026-12089 | [WS Optimize – All-in-One Speed Booster & Cache Tools <= 3.3.19 - Authenticated (Editor+) Arbitrary File Read](./plugins/lws-optimize/CVE-2026-12089/README.md) | WS Optimize – All-in-One Speed Booster & Cache Tools | `lws-optimize` | Arbitrary File Read | Medium (4.9) |


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
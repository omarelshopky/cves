# WordPress vulnerabilities

WordPress findings, split by component type. See the [root index](../README.md) for the cross-ecosystem master table.

## Plugins

| CVE                   | Name                                                                                                                                                                                                                                                                                                                        | Plugin                                                                      | Slug                                 | Type                           | Severity     |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------ | ------------------------------ | ------------ |
| CVE-2026-12089        | [WS Optimize – All-in-One Speed Booster & Cache Tools <= 3.3.19 - Authenticated (Editor+) Arbitrary File Read](./plugins/lws-optimize/CVE-2026-12089/README.md)                                                                                                                                                             | WS Optimize – All-in-One Speed Booster & Cache Tools                        | `lws-optimize`                       | Arbitrary File Read            | Medium (4.9) |
| CVE-2026-16042        | [LWS Optimize < 3.4 - Subscriber+ Cache Deletion](./plugins/lws-optimize/CVE-2026-16042/README.md)                                                                                                                                                                                                                          | WS Optimize – All-in-One Speed Booster & Cache Tools                        | `lws-optimize`                       | Broken Access Control          | Medium (4.3) |
| CVE-2026-16297        | [Clearfy < 2.4.3 - Admin+ PHP Object Injection via Settings Import](./plugins/clearfy/CVE-2026-16297/README.md)                                                                                                                                                                                                             | Clearfy Cache – WordPress optimization plugin, Minify HTML, CSS & JS, Defer | `clearfy`                            | Insecure Deserialization       | Medium (4.1) |
| CVE-2026-14331        | [Subscribe2 < 10.46 - Reflected XSS via email Parameter](./plugins/subscribe2/CVE-2026-14331/README.md)                                                                                                                                                                                                                     | Subscribe2 – Form, Email Subscribers & Newsletters                          | `subscribe2`                         | Reflected Cross-Site Scripting | Medium (4.7) |
| Dup of CVE-2026-16296 | [Clearfy < 2.4.3 - Open Redirect via Cyrlitera 404 Handler](./plugins/clearfy/open-redirect-via-cyrlitera-component/README.md)                                                                                                                                                                                              | Clearfy Cache – WordPress optimization plugin, Minify HTML, CSS & JS, Defer | `clearfy`                            | Open Redirect                  | Medium (4.7) |
| CVE-2026-78001        | [Post and Page Builder by BoldGrid <= 1.27.13 - Authenticated (Contributor+) Stored Cross-Site Scripting via 'data-label' Attribute](./plugins/post-and-page-builder/CVE-2026-78001/README.md)                                                                                                                              | Post and Page Builder by BoldGrid – Visual Drag and Drop Editor             | `post-and-page-builder`              | Stored Cross-Site Scripting    | Medium (6.4) |
| -                     | [Post and Page Builder by BoldGrid – Visual Drag and Drop Editor <= 1.27.10 - Contributor+ Stored Cross-Site Scripting via data-alpha Attribute](./plugins/post-and-page-builder/contributor-stored-xss-via-data-alpha-attribute/README.md)                                                                                 | Post and Page Builder by BoldGrid – Visual Drag and Drop Editor             | `post-and-page-builder`              | Stored Cross-Site Scripting    | Medium (6.4) |
| -                     | [Post and Page Builder by BoldGrid – Visual Drag and Drop Editor <= 1.27.10 - Contributor+ Stored Cross-Site Scripting via data-bg-uuid Attribute](./plugins/post-and-page-builder/contributor-stored-xss-via-data-bg-uuid-attribute/README.md)                                                                             | Post and Page Builder by BoldGrid – Visual Drag and Drop Editor             | `post-and-page-builder`              | Stored Cross-Site Scripting    | Medium (6.4) |
| -                     | [Post and Page Builder by BoldGrid – Visual Drag and Drop Editor <= 1.27.10 - Contributor+ Stored Cross-Site Scripting via data-hover-bg-class, data-hover-image-url, data-hover-bg-overlaycolor, data-hover-bg-position, Attribute](./plugins/post-and-page-builder/contributor-stored-xss-via-hover-attributes/README.md) | Post and Page Builder by BoldGrid – Visual Drag and Drop Editor             | `post-and-page-builder`              | Stored Cross-Site Scripting    | Medium (6.4) |
| CVE-2026-78068        | [Table Field Add-on for ACF and SCF <= 1.3.35 - Authenticated (Contributor+) Stored Cross-Site Scripting via Table Cell Content](./plugins/advanced-custom-fields-table-field/CVE-2026-78068/README.md)                                                                                                                     | Table Field Add-on for ACF and SCF                                          | `advanced-custom-fields-table-field` | Stored Cross-Site Scripting    | Medium (6.4) |
| CVE-2026-87869        | [Filter Everything — WordPress & WooCommerce Filters <= 1.9.6 - Reflected Cross-Site Scripting via Elementor Posts Widget Pagination URL](./plugins/filter-everything/CVE-2026-87869/README.md)                                                                                                                             | Filter Everything — WordPress & WooCommerce Filters                         | `filter-everything`                  | Reflected Cross-Site Scripting | Medium (6.1) |


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
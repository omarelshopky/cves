# CVEs

Security research and coordinated vulnerability disclosures by [**Omar Elshopky**](https://omarelshopky.com/).

This repository is an index and archive of vulnerabilities I've discovered, organized
by ecosystem. Each finding has its own directory containing a writeup, a
proof-of-concept, and supporting evidence (screenshots / recordings).

> [!WARNING]
> All proof-of-concept code in this repository is provided for **educational and
> defensive purposes only**, and covers vulnerabilities that have completed
> coordinated disclosure and are patched. Do not use any material here against
> systems you do not own or are not explicitly authorized to test. Findings that are
> still under embargo are **not** published here until disclosure is complete.

## Ecosystems/Vendors

| Ecosystem/Vendor | Findings | Index                               |
| --------- | -------: | ----------------------------------- |
| WordPress |        1 | [wordpress/](./wordpress/README.md) |
| Eleveo    |       10 | [eleveo/](./eleveo/README.md)       |

## Master index

| CVE            | Name                                                                                                                                                                      | Ecosystem/Vendor | Component/Software                                            | Type                  | Severity (CVSS:4.0) |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ------------------------------------------------------------- | --------------------- | ------------------- |
| CVE-2026-12089 | [WS Optimize – All-in-One Speed Booster & Cache Tools <= 3.3.19 - Authenticated (Editor+) Arbitrary File Read](./wordpress/plugins/lws-optimize/CVE-2026-12089/README.md) | WordPress        | WS Optimize – All-in-One Speed Booster & Cache Tools (plugin) | Arbitrary File Read   | Medium (4.9)        |
| CVE-2026-15373 | [Eleveo Call Recording Software 9.7.0 userAddAction.do role Improper Authorization](./eleveo/call-recording-software/CVE-2026-15373/README.md)                            | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |
| CVE-2026-15374 | [Eleveo Call Recording Software 9.7.0 Group Interface roleAddAction.do Improper Authorization](./eleveo/call-recording-software/CVE-2026-15374/README.md)                 | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |
| CVE-2026-15375 | [Eleveo Call Recording Software 9.7.0 LDAP User Interface /callrec/users_ldap.jsp Improper Authorization](./eleveo/call-recording-software/CVE-2026-15375/README.md)      | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |
| CVE-2026-15376 | [Eleveo Call Recording Software 9.7.0 statisticReportAction.do Improper Authorization](./eleveo/call-recording-software/CVE-2026-15376/README.md)                         | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |
| CVE-2026-15377 | [Eleveo Call Recording Software 9.7.0 /callrec/sendlogfile Improper Authorization](./eleveo/call-recording-software/CVE-2026-15377/README.md)                             | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |
| CVE-2026-15470 | [Eleveo Call Recording Software 9.7.0 /callrec/group.jsp Improper Authorization](./eleveo/call-recording-software/CVE-2026-15470/README.md)                               | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |
| CVE-2026-15471 | [Eleveo Call Recording Software 9.7.0 pci_dss_status.jsp Improper Authorization](./eleveo/call-recording-software/CVE-2026-15471/README.md)                               | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |
| CVE-2026-15472 | [Eleveo Call Recording Software 9.7.0 composeEmailAction.do Improper Authorization](./eleveo/call-recording-software/CVE-2026-15472/README.md)                            | Eleveo           | Call Recording Software                                       | Broken Access Control | Medium (5.3)        |

## Repository layout

```
cves/
├── README.md                      # this file - master index
└── <ecosystem>/                   # e.g. wordpress/
    ├── README.md                  # per-ecosystem index
    └── <component-type>/          # e.g. plugins / themes / core
        └── <slug>/                # canonical component slug
            └── <CVE>/             # one directory per finding
                ├── README.md      # advisory + disclosure timeline
                ├── poc.py         # if applicable
                └── screenshots/
```

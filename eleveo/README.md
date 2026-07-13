# Eleveo vulnerabilities

[Eleveo](https://www.eleveo.com/) findings, split by software. See the [root index](../README.md) for the cross-vendor master table.

| CVE            | Name                                                                                                                                                          | Software                | Type                  | Severity     |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | --------------------- | ------------ |
| CVE-2026-15373 | [Eleveo Call Recording Software 9.7.0 userAddAction.do role Improper Authorization](./call-recording-software/CVE-2026-15373/README.md)                       | Call Recording Software | Broken Access Control | Medium (5.3) |
| CVE-2026-15374 | [Eleveo Call Recording Software 9.7.0 Group Interface roleAddAction.do Improper Authorization](./call-recording-software/CVE-2026-15374/README.md)            | Call Recording Software | Broken Access Control | Medium (5.3) |
| CVE-2026-15375 | [Eleveo Call Recording Software 9.7.0 LDAP User Interface /callrec/users_ldap.jsp Improper Authorization](./call-recording-software/CVE-2026-15375/README.md) | Call Recording Software | Broken Access Control | Medium (5.3) |
| CVE-2026-15376 | [Eleveo Call Recording Software 9.7.0 statisticReportAction.do Improper Authorization](./call-recording-software/CVE-2026-15376/README.md)                    | Call Recording Software | Broken Access Control | Medium (5.3) |
| CVE-2026-15377 | [Eleveo Call Recording Software 9.7.0 /callrec/sendlogfile Improper Authorization](./call-recording-software/CVE-2026-15377/README.md)                        | Call Recording Software | Broken Access Control | Medium (5.3) |
| CVE-2026-15470 | [Eleveo Call Recording Software 9.7.0 /callrec/group.jsp Improper Authorization](./call-recording-software/CVE-2026-15470/README.md)                          | Call Recording Software | Broken Access Control | Medium (5.3) |

## Layout

```
eleveo/
├── README.md                      # this file
└── <software-slug>/               # canonical software slug
    └── <cve>/
        ├── README.md
        ├── poc.py
        └── screenshots/
```
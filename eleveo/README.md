# Eleveo vulnerabilities

[Eleveo](https://www.eleveo.com/) findings, split by software. See the [root index](../README.md) for the cross-vendor master table.

| CVE             | Name                                                                                                                                                          | Software                | Type                                              | Severity     |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------- | ------------ |
| CVE-2026-15373  | [Eleveo Call Recording Software 9.7.0 userAddAction.do role Improper Authorization](./call-recording-software/CVE-2026-15373/README.md)                       | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15374  | [Eleveo Call Recording Software 9.7.0 Group Interface roleAddAction.do Improper Authorization](./call-recording-software/CVE-2026-15374/README.md)            | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15375  | [Eleveo Call Recording Software 9.7.0 LDAP User Interface /callrec/users_ldap.jsp Improper Authorization](./call-recording-software/CVE-2026-15375/README.md) | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15376  | [Eleveo Call Recording Software 9.7.0 statisticReportAction.do Improper Authorization](./call-recording-software/CVE-2026-15376/README.md)                    | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15377  | [Eleveo Call Recording Software 9.7.0 /callrec/sendlogfile Improper Authorization](./call-recording-software/CVE-2026-15377/README.md)                        | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15470  | [Eleveo Call Recording Software 9.7.0 /callrec/group.jsp Improper Authorization](./call-recording-software/CVE-2026-15470/README.md)                          | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15471  | [Eleveo Call Recording Software 9.7.0 pci_dss_status.jsp Improper Authorization](./call-recording-software/CVE-2026-15471/README.md)                          | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15472  | [Eleveo Call Recording Software 9.7.0 composeEmailAction.do Improper Authorization](./call-recording-software/CVE-2026-15472/README.md)                       | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15473  | [Eleveo Call Recording Software 9.7.0 Recorded Calls Page restoreCallAction.do Improper Authorization](./call-recording-software/CVE-2026-15473/README.md)    | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-15474  | [Eleveo Call Recording Software 9.7.0 /callrec/audio.jsp callId Improper Authorization](./call-recording-software/CVE-2026-15474/README.md)                   | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-85405  | [Eleveo Call Recording Software 9.7.0 Multiple Stored Cross-Site Scripting](./call-recording-software/CVE-2026-85405/README.md)                               | Call Recording Software | Multiple Stored Cross-Site Scripting              | Medium (5.1) |
| CVE-2026-85406  | [Eleveo Quality Management 9.7.0 Multiple Stored Cross-Site Scripting](./quality-management/CVE-2026-85406/README.md)                                         | Quality Management      | Multiple Stored Cross-Site Scripting              | Medium (5.1) |
| CVE-2026-85407  | [Eleveo Quality Management 9.7.0 Conversation Events Denial of Service](./quality-management/CVE-2026-85407/README.md)                                        | Quality Management      | Denial of Service                                 | Medium (5.3) |
| CVE-2026-85408  | [Eleveo Quality Management 9.7.0 Conversation Events createdBy Dynamically-Determined Object Attributes](./quality-management/CVE-2026-85408/README.md)       | Quality Management      | Mass Assignment                                   | Medium (5.3) |
| CVE-2026-85409  | [Eleveo Quality Management 9.7.0 Arbitrary File Write](./quality-management/CVE-2026-85409/README.md)                                                         | Quality Management      | Arbitrary File Write                              | Medium (5.3) |
| CVE-2026-101141 | [Eleveo Call Recording Software 9.7.0 Multiple Reflected Cross-Site Scripting](./call-recording-software/CVE-2026-101141/README.md)                           | Call Recording Software | Multiple Reflected Cross-Site Scripting           | Medium (5.1) |
| CVE-2026-101142 | [Eleveo Quality Management 9.7.0 Local File Disclosure and Arbitrary File Deletion](./quality-management/CVE-2026-101142/README.md)                           | Quality Management      | Local File Disclosure and Arbitrary File Deletion | Medium (5.3) |
| CVE-2026-101143 | [Eleveo Quality Management 9.7.0 QMBODownload Information Disclosure](./quality-management/CVE-2026-101143/README.md)                                         | Quality Management      | Information Disclosure                            | Medium (5.3) |
| CVE-2026-101144 | [Eleveo Call Recording Software 9.7.0 Query Builder searchAction.do Access Control](./call-recording-software/CVE-2026-101144/README.md)                      | Call Recording Software | Broken Access Control                             | Medium (5.3) |
| CVE-2026-101145 | [Eleveo Call Recording Software 9.7.0 User Management userAddAction.do LDAP Injection](./call-recording-software/CVE-2026-101145/README.md)                   | Call Recording Software | LDAP Injection                                    | Medium (5.3) |

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
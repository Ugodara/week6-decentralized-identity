| Test        | Fixture / Request       | Expected   | Observed   | Reason Code    | Explanation            |
| ----------- | ----------------------  |---------   | ---------- | -------------- | -----------------------|
| **Valid     | `valid.json`            |  **ALLOW** | **ALLOW**  |`SUCCESS` / `OK`|  All checks passed.    |           
|credential** | + correct holder + `read|            |            |                |                        | 
|             | -training-lab`          |            |            |                |                        |
|-------------|-------------------------|------------|------------|----------------|------------------------|
| **Untrusted | `untrusted-issuer       | **DENY**   | **DENY**   |`UNTRUSTED_ISSUER`| Issuer not in trust list.
| issuer**    | .json`                  |            |            |                |                         |
|-------------|-------------------------|------------|------------|----------------|-------------------------|
| **Expired   | `expired.json`          | **DENY**   | **DENY**   |`EXPIRED_CREDENTIAL`| `validUntil` is in the past.
| credential**|                         |            |            |                |                          |
|-------------|-------------------------|------------|------------|----------------|--------------------------|
| **Missing   |  `missing-claim.json`   | **DENY**   | **DENY**   | `MISSING_CLAIM`| Required status          |
| claim**     |                         |            |            |                | field missing.           |
|-------------|-------------------------|------------|------------|----------------|--------------------------|
| Unauthorised| valid.json +            | **DENY**   | **DENY**   |`ACTION_NOT_ALLOWED`| Action not allowed by|
| action      | delete-root-database    |            |            |                | policy                   |
|-------------|-------------------------|------------|------------|----------------|--------------------------|

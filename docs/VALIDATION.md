# Validation evidence

**Terms used here:** A fixture is test data or a test setup used instead of real business records. Role-based access control gives people or services permissions according to their roles.

| Check | Recorded local result |
| --- | --- |
| Extracted Node field/bank tests plus key-identifier tests | 13 passed: nine original tests and four public helper checks |
| Python actual-crypto reference | 13 passed |
| Demonstration | Seven checks passed |
| Terraform | Schema validation and three mock plans passed; no apply |
| Browser | Desktop/mobile, rerun/tabs and origin/asset denials passed |
| Workflow syntax | actionlint 1.7.12 passed; no hosted CI dispatched |
| Source secret scan | Trivy 0.75.0: zero findings in this selected input |

The [machine record](validation-results.json) includes date, counts and source hashes. Screenshots come from working local code; no fake terminal or portal transcript is used.

## Important distinctions

- Original Node tests inject wrapper fixtures to isolate AES/context behavior; they do not prove Key Vault or real RSA wrapping.
- The Python exercise does use real AES-256-GCM and RSA-OAEP-256 with temporary in-memory keys. It is not managed-identity, Azure policy or HSM acceptance.
- Rotation/rewrap/missing-version cases are local simulations, not production operations or a data migration.
- No original records, actual key material or live vault identifiers are included. No private key is written or returned by the workbench.
- Public AAD labels and Python envelope format are reference adaptations. They must not be mass-applied to existing stored records.

## Reproduce

```bash
npm run test:source
python -B -m unittest discover -s tests -v
python -B -m lab demo
```

Actual nonproduction Key Vault/RBAC/terminal captures can be added later under [the screenshot plan](SCREENSHOT-PLAN.md). Live wrap/unwrap, network access and recovery must retain their own accepted evidence.

## Tools and utilities documentation review — November 7, 2026

Added a prominent README table naming the relevant tools/services and their jobs. The wording distinguishes actual platform components, operating utilities, selected source adapters, optional preparation and local teaching examples. Relevant step headings name their tools while the four-step order and explanatory sentences remain unchanged.

This editorial pass did not change application code, dependencies, infrastructure, workflows or cloud settings. Existing tests and screenshots retain their original evidence scope; no application suite, live scanner, browser sign-in, paid request or GitHub Actions run was executed for this wording update.

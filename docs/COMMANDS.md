# Commands and expected results

Run from the repository root. The default commands use fictional values and ephemeral local keys, not Azure resources.

## 1. Setup

Use Python 3.12 and Node 22.18+ (accepted source run: Node 22.23.2).

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

PowerShell without changing execution policy:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm.cmd run test:source
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The source tests need no Node package install because they use built-in crypto and injected wrapper fixtures. The optional Azure adapter declares SDK dependencies separately; default tests do not load it or try a developer/managed-identity credential.

## 2. Actual source and public crypto checks

```bash
npm run test:source
python -B -m unittest discover -s tests -v
python -B -m lab demo
```

Node prints TAP counts; Python should finish in `OK`. The CLI JSON contains seven checks with `passed: true`, plus an example envelope. Its base64 fields are ciphertext/metadata, not an exported private RSA key or raw DEK. Keys exist only in this process, so the printed envelope is not a recoverable backup after the process exits.

## 3. Focused failure and rotation checks

```bash
python -B -m unittest discover -s tests -p test_envelope.py -k tamper -v
python -B -m unittest discover -s tests -p test_envelope.py -k wrong -v
python -B -m unittest discover -s tests -p test_envelope.py -k rotation -v
python -B -m unittest discover -s tests -p test_envelope.py -k missing_version -v
```

A negative test passes when authentication/key selection correctly fails. The local rewrap case is not a migration command for production records.

## 4. Workbench

```bash
python -B -m lab serve --port 8011
```

Open [the loopback page](http://127.0.0.1:8011), run the demonstration and inspect Validation/Evidence. Stop with Ctrl+C. Each run creates fresh ephemeral keys and fictional ciphertext. No private-key export is exposed by the server.

## 5. Terraform without cloud mutation

```bash
terraform -chdir=infra init -backend=false -input=false
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra validate
terraform -chdir=infra test -filter=tests/encryption.tftest.hcl
```

Provider initialization downloads pinned providers. Tests use mock providers and plan commands. They do not create a vault, provision a key, grant access or prove private caller reachability. Real values/state remain outside Git; no apply/destroy is part of the local procedure.

## 6. Optional read-only Azure metadata inspection

These are operating examples, not executed for this public preparation. They require an already approved signed-in identity and exact reviewed values. Do not paste real key URIs/resource IDs into a public screenshot.

```bash
az keyvault key show --id "$WRAPPING_KEY_VERSION_URI" --query '{enabled:attributes.enabled,expires:attributes.expires,keyOperations:key.keyOps}' --output json
az role assignment list --scope "$WRAPPING_KEY_ARM_SCOPE" --include-inherited --query '[].{role:roleDefinitionName,principalType:principalType}' --output table
```

The first command reads version metadata, not the private key. The second inspects role scope; it is not an unwrap permission test. Actual wrap/unwrap, backup/restore or rotation needs its own accepted procedure and evidence.

## Manual CI and cleanup

CI is manual-only: setup Node/Python, run the source tests, install Python requirements, run unit tests and the CLI demo. No workflow was dispatched by this documentation.

```bash
git status --short --ignored
git diff --check
```

Remove only your own temporary files. Do not delete old keys, weaken purge protection or copy production state just to clean up a lab. Never commit PEM/PFX material, real records, data keys or sensitive debug output.

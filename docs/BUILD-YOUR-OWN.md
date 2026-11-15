# Build your own from scratch: Azure Envelope Encryption

Your own field-encryption script that wraps a fresh AES data key with a versioned Azure Key Vault RSA key before a value could be stored in SQL.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

## Prerequisites

Python, Azure CLI, a new Key Vault/RSA wrapping key and a runtime identity permitted to read/wrap/unwrap that key. The vault setup administrator and runtime key user are separate responsibilities.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

## Create your project folder

Choose a new folder name. These first commands create a blank project; an optional `git init` gives it its own history. Create parent directories in your editor when a later step introduces a nested file.

```bash
mkdir my-azure-envelope-encryption
cd my-azure-envelope-encryption
git init
```

Create `.gitignore` before saving credentials or build outputs:

```gitignore
.venv/
node_modules/
.env
.env.*
local.settings.json
credentials.json
token.json
*.pem
*.key
*.tfstate*
*.tfplan
.terraform/
private*/
captures/
backups/
batch.json
reports/
out/
app-config.local.yaml
```

The source/file snippets are a starting implementation you type or paste into the named files. Replace `YOUR_*`, names, regions and addresses only with values from your own lab; do not place real client/employee records in a test project. Keep your terminal in this project root unless a step explicitly changes directory.

Before a first commit, set your own repository-local author with `git config user.name "YOUR_NAME"` and `git config user.email "YOUR_PUBLIC_COMMIT_EMAIL"`. Review `git status --short` and the staged diff before publishing; ignored local files are not a substitute for reviewing what you upload.

## Step 1 — Create your vault and wrapping key

**Where:** Azure Portal → Key Vault → Keys.

Create a vault with RBAC and appropriate network/recovery settings, then create an RSA wrapping key through your setup administrator. Record the key's full versioned ID privately and assign the intended runtime identity only the required crypto operations.

**Check before continuing:** A specific key version exists and the intended runtime caller can reach/use it.

## Step 2 — Install your crypto dependencies

**Where:** Your new project folder.

Create a virtual environment and install the libraries below. Record their resolved versions and keep credentials, encrypted business samples and Terraform state out of Git.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install cryptography azure-identity azure-keyvault-keys
.venv/bin/python -m pip freeze > requirements.lock.txt
```

**Check before continuing:** The selected Python environment imports the local and Azure crypto clients.

## Step 3 — Create the field wrapper

**Where:** Your editor.

Create encrypt_field.py below. The associated record ID is authenticated context; storing an envelope for one person must not allow another person's record context to decrypt it.

Create **`encrypt_field.py`** with the following contents:

```python
import os, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from azure.identity import AzureCliCredential
from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm

def b64(data): return base64.b64encode(data).decode('ascii')
credential = AzureCliCredential()
key_id = os.environ['WRAPPING_KEY_VERSION_ID']
crypto = CryptographyClient(key_id, credential)
dek = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
aad = b'employee:LAB-001:private-field:v1'
ciphertext = AESGCM(dek).encrypt(nonce, b'fictional-private-value', aad)
wrapped = crypto.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, dek).encrypted_key
envelope = {'schema': 1, 'key_id': key_id, 'nonce': b64(nonce),
            'ciphertext': b64(ciphertext), 'wrapped_key': b64(wrapped)}
recovered = crypto.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, wrapped).key
assert AESGCM(recovered).decrypt(nonce, ciphertext, aad) == b'fictional-private-value'
print(json.dumps({'round_trip': True, 'envelope_fields': list(envelope)}))
```

**Check before continuing:** The file separates the encrypted value, nonce, wrapped data key and wrapping-key version.

## Step 4 — Run with your intended identity

**Where:** Your private terminal configuration.

Sign in as the intended key user, configure WRAPPING_KEY_VERSION_ID without committing it, and run the script. This deliberately makes real Key Vault operations in your own lab; do not substitute production records.

```bash
az login
.venv/bin/python encrypt_field.py
```

**Check before continuing:** The script reports a successful fictional round trip without printing plaintext or a data key.

## Step 5 — Prove failure and storage boundaries

**Where:** Your own tests and SQL design.

Add tests for a changed ciphertext/tag, a different record-ID context and missing unwrap permission; each must fail without returning a value. Store the envelope in SQL only after encryption, and enforce database record authorization separately from the ability to unwrap a key.

**Check before continuing:** Integrity, identity context, key access and SQL ownership are distinct tested controls.

## Step 6 — Plan rotation and recovery before cleanup

**Where:** Your key/version inventory.

Keep old key versions available for data that still references them, test backup/recovery access and choose explicit rewrap/re-encrypt procedures if rotating. Never delete an old key merely because a newer one exists; remove only a dedicated lab after its encrypted data is no longer required.

**Check before continuing:** The reader can explain encryption before SQL storage and why key deletion can destroy recovery.

## Verification and your own screenshots

| Evidence | What to record | Your result |
| --- | --- | --- |
| New build | Your own files/resource settings and tool versions | Not yet recorded |
| Working path | The actual successful request, configuration or recovery result | Not yet recorded |
| Failure boundary | A meaningful denied, malformed, stale or failed case | Not yet recorded |
| Recovery / cleanup | What you restored or removed and what remains billed | Not yet recorded |

Capture your own architecture/configuration, one working result and one failure/recovery result. Keep tokens, credentials, personal records and private identifiers out of public screenshots. Existing portfolio images are references, not evidence that you performed these steps.

## Troubleshooting order

1. Confirm the named file, working directory and selected tool/interpreter.
2. Check the exact input and resource/account selected for the failing step.
3. Separate identity permission, network/DNS reachability and application validation.
4. Keep the actual error and reconcile an unknown write outcome before repeating it; do not widen access or repeat paid operations blindly.

The numbered steps describe a build procedure. Local syntax checks, an accepted API request, a completed hosted operation and a human verification are different evidence levels; fill in the verification table with what you actually observed.

## Official implementation references

- [learn.microsoft.com — quick-create-python](https://learn.microsoft.com/en-us/azure/key-vault/keys/quick-create-python)
- [cryptography.io — aead](https://cryptography.io/en/latest/hazmat/primitives/aead/)

The walkthrough layout follows the prerequisites → creation/configuration → test → verification → troubleshooting → cleanup pattern of the [Splunk project reference](https://github.com/davidharris6/splunk-siem-log-analysis). Its Splunk-specific settings are not copied into unrelated projects.

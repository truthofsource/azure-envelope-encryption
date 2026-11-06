# Actual encryption source excerpts

```bash
npm run test:source
```

The default tests need only Node 22.18+; they do not import the Azure SDK adapter or call Key Vault. The suite includes original field/bank tests plus public helper-validation tests. Wrapper fixtures are intentionally isolated from real RSA/service behavior.

`keyVaultAdapter.ts` declares its Azure SDK dependencies in the root package metadata. Integrating that optional module requires installing the SDKs, a reviewed key URI, a supported credential and scoped wrap/unwrap permission. No credential or live call is activated by the default source test command.

Read [the source map](../docs/SOURCE-MAP.md) before adapting any stored format or authenticated namespace.

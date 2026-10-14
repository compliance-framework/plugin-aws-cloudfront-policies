# AWS CloudFront policies

Standalone OPA/Rego policy bundle for CloudFront distribution evidence emitted by the `plugin-aws-cloudfront` collector.

## Input schema

Each policy evaluates one CloudFront distribution at a time using:

- `input.account_id`
- `input.distribution_id`
- `input.arn`
- `input.domain_name`
- `input.status`
- `input.enabled`
- `input.certificate_arn` (omitted when the distribution has no ACM certificate)
- `input.cache_behaviours`: a list of `{path_pattern, viewer_protocol_policy}`, including the default cache behaviour as path `/*`
- `input.tags`

## Current coverage

| Policy | Checks | Controls |
| --- | --- | --- |
| `cloudfront_require_https_viewer_protocol` | no cache behaviour uses `viewer_protocol_policy` `allow-all` (unencrypted HTTP); each offending behaviour is reported with its path pattern | CC6.7 |

## Policy data

`policies/data.json` defines `approved_viewer_protocol_policies` (`["redirect-to-https", "https-only"]`), but no policy reads it today: `cloudfront_require_https_viewer_protocol` flags `allow-all` directly, so overriding this key has no effect.

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.

## Releasing

- Releases come from release-please PRs: merging one tags `vX.Y.Z` and publishes the policy bundle.
- Release candidates (`vX.Y.Z-rcN`) come from the `cut-prerelease` workflow.

## Related repositories

- [plugin-aws-cloudfront](https://github.com/compliance-framework/plugin-aws-cloudfront)

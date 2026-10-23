# Contributing to Keenrig

Thanks for helping. Bug reports, app manifests and fixes are all welcome.

## Before you open a pull request

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Build the Admin UI once (`make ui`, needs Node 20+), then run `make test-short` (needs Go 1.26).
3. Keep the change focused — one topic per pull request.

## Adding an app to the catalog

Catalog apps live in `keenrig-catalog/manifests/<id>.json`. A manifest must:

- pin the image by digest (`sha256:…`), not only by tag;
- declare every persistent directory under `volumes`, or data is lost on the first update;
- put per-install secrets in `secret_env`, never as fixed values in `env`;
- use an app whose licence allows it to be installed on a user's own server.

See `keenrig-node/internal/catalog/catalog.go` for the full list of fields and checks.

## Sign your commits (DCO)

Keenrig uses the [Developer Certificate of Origin](https://developercertificate.org/).
Add a `Signed-off-by` line to every commit to certify that you wrote the change or have the
right to submit it:

```
git commit -s -m "catalog: add Uptime Kuma"
```

## Licence of contributions

Contributions to files outside `keenrig-node/proprietary/` are accepted under the GNU Affero
General Public License v3.0, the licence of this repository. We do not accept contributions to
`keenrig-node/proprietary/`.

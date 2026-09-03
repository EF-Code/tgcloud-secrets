# Release and supply-chain checklist

1. Review source, migrations, dependency lockfile, and generated package file
   from the same commit.
2. Run `npm ci --ignore-scripts`, `npm test`, `npm run fuzz`, `npm run check`,
   `npm audit --omit=dev`, `npm run secret-scan`, `npm run license-check`, and
   `npm pack --dry-run`.
3. Generate the CycloneDX SBOM with `node scripts/generate-sbom.mjs` and
   retain it beside the artifact.
4. Build once from a pinned base-image digest. Scan the image, sign it, and
   attach an immutable provenance attestation in the external release system.
5. Promote that exact package/image digest through an isolated staging
   environment. Exercise synthetic authorized traffic, revoke/restore, KMS
   failure, limiter failure, migration compatibility, backup restore, and
   rollback before canary.
6. Keep publishing credentials out of forked/untrusted pull-request jobs.
   Protect the default branch and require the CI checks plus independent
   review before release.
7. Review the pinned CodeQL and dependency-review workflow results for the
   exact commit. Configure container scanning, artifact signing, provenance
   verification, and the approved vulnerability-exception process before
   promotion.

Image signing, provenance attestations, branch protections, dependency update
SLAs, vulnerability exceptions, and external SAST/CodeQL execution require
repository-host and organization configuration; they are not claimed by the
local scripts.

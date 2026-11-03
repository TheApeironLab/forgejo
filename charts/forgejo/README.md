# Code application chart

This repository owns the **Code** application chart, powered by Forgejo. It deploys one Forgejo Helm release
(stable application ID `git`, Chart name `forgejo`) using the reviewed, digest-pinned upstream container image.
The application title is configured as **Code** through Forgejo’s root `APP_NAME` setting (`GITEA____APP_NAME`).
The source mirror retains the upstream source and license; the chart does not build
or upgrade the upstream application as a side effect of installation.

Supply site-specific `domain`, `registry`, `postgresHost`, storage and reviewed image
coordinates. Before Helm apply, the installer prepares the PostgreSQL `git` database,
namespace-local `git-db` (`password`), `registry-pull`, `chentu-ca` (`ca.crt`) and the
`git-oidc` (`issuer`, `client-id`, `client-secret`) references for native SSO.
The installer must create the local recovery administrator before enabling SSO and
register the Keycloak login source in Forgejo after the first startup. The chart
alone does not create IAM clients, database users or the login source. Never put an
IAM administrator credential in chart values or application Pods.

The application-owned chart keeps the existing native SSO default. Native SSO and
the optional proxy mode are mutually exclusive; neither permits anonymous access
or treats an authenticated platform user as automatically authorized for Git.

```sh
helm lint charts/forgejo --values charts/forgejo/values-vasi.example.yaml
helm template git charts/forgejo --namespace git --values charts/forgejo/values-vasi.example.yaml
python3 release/package.py --output /absolute/path/outside/this/repository
```

`Application chart` produces `forgejo-charts`, containing the standard `.tgz` plus
`forgejo-chart-release.json` with source commit, archive SHA-256 and size. Production
packaging requires clean committed sources. `--development` is only for local
validation. Every published chart version is immutable.

The deployment templates were moved from Chentu; `files/origin.json` records their
source commit. Importing this chart does not prove application or SSO readiness;
verify actual login, per-user authorization, Git operations and persistent data.
Helm rollback cannot restore database migrations or IAM changes.

Forgejo is GPL-3.0-or-later. Keep upstream license/copyright notices and provide
corresponding source when conveying covered binaries, including any modifications.

# Threat model

A STRIDE review of dartvulncheck as it runs in CI or on a developer's
machine. It lists what the tool is trusted with, where untrusted input
enters, what each category of threat looks like here, and what the code
does about it. Status is one of **mitigated** (the code prevents it, with a
test), **accepted** (known and left as is, with the reason), or **out of
scope** (not this tool's problem to solve).

## What is at stake

| Asset | Why it matters |
| --- | --- |
| A1 The verdict | The exit code is a CI gate. A false "no problems" lets a vulnerable build through; a verdict that can be weakened silently is the same thing one step removed. |
| A2 `GITHUB_TOKEN` | Usually the Actions token (`contents: read`), sometimes a personal token. It must reach api.github.com and nothing else. |
| A3 The host | The tool reads a few project files and runs `flutter` and `dart`. It must not run anything else, and it writes nothing. |
| A4 Dependency names and versions | Mildly confidential for packages from a private registry. They are sent to the advisory sources by design. |

## Where untrusted input enters

| Boundary | Input | Who controls it |
| --- | --- | --- |
| B1 Project files | `pubspec.lock`, `pubspec.yaml` (`ignored_advisories`), `.fvmrc`, `.fvm/fvm_config.json` | Anyone who can push to the repository, including the author of a pull request the CI runs on |
| B2 Network | Responses from api.github.com, pub.dev and api.osv.dev | The services; for pub.dev package metadata (`repository`, `homepage`), the package's publisher |
| B3 Environment | `GITHUB_TOKEN`, `DARTVULNCHECK_*_URL`, `PATH`, the `flutter` and `dart` executables | Whoever configures the CI job or the machine |
| B4 Command line | Options and directories | The same |

## Spoofing

| ID | Threat | Status | What the code does |
| --- | --- | --- | --- |
| S1 | A fake advisory source, reached through `DARTVULNCHECK_*_URL`, answers "no advisories" (A1) or receives the token (A2). | mitigated | Overrides must be `https`; `http` is accepted for localhost only. Every override in effect is printed as a warning on every run. Residual: whoever sets the CI job's environment already controls the job. |
| S2 | A fake `flutter` or `dart` on `PATH` reports a safe SDK version. | accepted | On POSIX, `PATH` belongs to the CI job or the user. On Windows the current directory was also searched; see E1. |
| S3 | A stale or forged `.fvmrc`, or a wrong `--sdk-version`, names an SDK version that nothing builds with. | mitigated | The version is still taken from there (with FVM the pin is what builds), but `flutter --version` on `PATH` is asked as well and a difference is warned about. The report names the origin of the version it checked. |
| S4 | A package's pub.dev metadata points at a repository of the publisher's choosing, whose advisories then speak for other packages in the lock. | mitigated | A repository's advisories count only for the packages pub.dev maps to that repository. Owner and repository names are validated before they become an API path. Residual: an unnamed advisory in such a repository shows as "unverified" for that package, not counted unless `--strict`. |
| S5 | A TLS peer impersonating a source. | mitigated | HTTPS with the system's roots. A handshake failure counts as unreachable: fall back to OSV.dev, else exit 1. |

## Tampering

| ID | Threat | Status | What the code does |
| --- | --- | --- | --- |
| T1 | `pubspec.lock` is edited so that the checked versions are not the built ones. | accepted | The lock is the input by definition. Run `dart pub get --enforce-lockfile` in the build job so that the lock the tool read is the lock the build used. |
| T2 | A finding is silenced with `ignored_advisories` or `--ignore`. | accepted, made visible | This is pub's own mechanism. Ignored findings are listed under "Ignored" in the text report, kept in the JSON with `"ignored": true`, and counted in the summary, so a new ignore is readable in the CI log. |
| T3 | Responses altered in transit. | mitigated | HTTPS; redirects are not followed; plain `http` is refused except on localhost. |
| T4 | A source itself serves false data (a compromised GitHub, pub.dev or OSV.dev). | out of scope | The sources are the trust root. The fallback does not help here: OSV.dev mirrors the GitHub database. |
| T5 | Package names in the lock crafted to alter a request (`,` in an `affects=` value, `/` in a pub.dev path). | mitigated | Names are URL-encoded or sent as JSON; a crafted name can at most add a harmless entry to a query. |

## Repudiation

| ID | Threat | Status | What the code does |
| --- | --- | --- | --- |
| R1 | A run cannot show afterwards what it checked against. | partly mitigated | The report names the SDK version and where it came from, the number of packages queried, and warns when a fallback or an endpoint override was used; the JSON carries the tool version. Accepted: no timestamp or source snapshot in the JSON. |
| R2 | Suppression leaves no trace. | mitigated | See T2. |

## Information disclosure

| ID | Threat | Status | What the code does |
| --- | --- | --- | --- |
| I1 | The token is sent to another host by following a `Link: rel="next"` URL or a redirect in a response. | mitigated | Pagination follows a link only within the origin of the configured API base. Redirects are not followed at all; dart:io would copy the `Authorization` header onto the redirected request whatever host it named. |
| I2 | The token is sent to a host chosen through `DARTVULNCHECK_GITHUB_API_URL`. | mitigated | See S1. |
| I3 | The token appears in output or an error message. | mitigated | Nothing prints headers or request URLs with credentials; errors carry a status code and a host. |
| I4 | A private registry URL with credentials in its userinfo, taken from `pubspec.lock`, is printed by `--verbose`. | mitigated | Only the host is printed. |
| I5 | Names and versions of every hosted package, including those from a private registry, are sent to GitHub, pub.dev and OSV.dev. | accepted | Inherent to asking the sources. A run that includes packages from a registry other than pub.dev says so in a warning; `--verbose` lists them. |

## Denial of service

| ID | Threat | Status | What the code does |
| --- | --- | --- | --- |
| D1 | A source keeps returning a "next page", forever. | mitigated | GitHub pagination and OSV `next_page_token` stop after 50 pages and report the response as unexpected. |
| D2 | A response of unbounded size fills memory. | mitigated | Bodies are read with a 16 MB cap; each request has a 30 s timeout and one retry. |
| D3 | A huge lock file causes thousands of requests. | accepted | Requests are bounded by the number of packages, with at most 8 pub.dev and 4 GitHub requests in flight. The global query batches 1000 packages per request. |
| D4 | A source is down or rate-limited, so CI fails. | accepted by design | "Could not check" exits 1 and cannot be silenced: a check that cannot run must not pass. A token raises the GitHub limit; `--no-repo-advisories` removes most requests. |
| D5 | A `pubspec.lock` crafted with YAML aliases to exhaust memory. | accepted | pub parses the same file first in any build, and whoever can commit the file can already run code in the CI job. |
| D6 | Regular expressions with pathological inputs. | mitigated by construction | Every pattern is linear; none nests quantifiers. |

## Elevation of privilege

| ID | Threat | Status | What the code does |
| --- | --- | --- | --- |
| E1 | On Windows, a `flutter.bat` or `dart.bat` committed to the project runs with the rights of whoever runs the check, because cmd.exe looks in the current directory before `PATH`. | mitigated | The executable is located on `PATH` first and started by its full path. A name on no `PATH` entry counts as not installed. |
| E2 | Input reaches a command line. | mitigated by construction | The only processes started are `flutter --version --machine` and `dart --version`, with fixed arguments; no shell on POSIX. |
| E3 | The tool changes the machine. | mitigated by construction | It writes no files and keeps no cache. |
| E4 | The CI token is more powerful than needed. | mitigated | The workflows in this repository request `contents: read`; advisories are readable with that. The publish workflow adds `id-token: write`: a short-lived OpenID Connect token that pub.dev accepts only from this repository and tag pattern, in place of a stored credential. |

## What users should still do

- Build with `dart pub get --enforce-lockfile` (or `flutter pub get --enforce-lockfile`), so the lock the tool checked is the lock that was built.
- Review changes to `pubspec.lock`, `pubspec.yaml` (`ignored_advisories`) and `.fvmrc` in pull requests. The report lists ignores and names the SDK version's origin, but it cannot tell a deliberate change from a hostile one.
- Give the job a token with `contents: read` only.
- Install a named version (`dart pub global activate dartvulncheck <version>`, or `--git-ref v<version>` from git) rather than the head of a branch.

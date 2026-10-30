# Examples

## In GitHub Actions

```yaml
vulncheck:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: subosito/flutter-action@v2
      with:
        channel: stable
    - run: dart pub global activate dartvulncheck 0.2.1
    - run: dart pub global run dartvulncheck
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

`GITHUB_TOKEN` lets the repository-advisory stage run and raises the API rate limit; the default Actions token is enough. Add a weekly `schedule` trigger as well: new advisories appear even when the code does not change.

## On a developer machine

```sh
dart pub global activate dartvulncheck 0.2.1
cd my_app
dartvulncheck                                # text report; exit 3 on findings
dartvulncheck --json > vulncheck.json        # machine-readable
dartvulncheck app packages/core              # several directories (monorepo)
dartvulncheck --fail-on high                 # ignore low and moderate findings
dartvulncheck --ignore GHSA-xxxx-xxxx-xxxx   # or ignored_advisories in pubspec.yaml
```

# Releasing

Releases of this crate are fairly automated.

To create a new release:

1. Make sure `CHANGELOG.md` is up-to-date and contain all modifications under the `[Unreleased]` section.
2. Trigger [this](https://github.com/monero-rs/monero-rs/actions/workflows/draft-new-release.yml) workflow with the desired version number.
3. Merge the resulting PR (watch your notifications).

The `[Unreleased]` section of `CHANGELOG.md` must contain all the changes that will be documented for the release.

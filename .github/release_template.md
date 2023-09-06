# Checklist for creating a new release

- [ ] Update `CHANGELOG.md` for the new version
- [ ] Change version number in `docs/source/schema.yml`, `docker/.version`
- [ ] Verify CI Tests
- [ ] Create release for the branch `develop`. Name it with the name of the version
- [ ] Merge the PR to the `main` branch

**Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.
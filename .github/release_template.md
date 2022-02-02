# Checklist for creating a new release

- [ ] Change version number in `settings.SPECTACULAR_SETTINGS`
- [ ] Verify CI Tests
- [ ] Create release for the branch `develop`
- [ ] Wait for dockerHub to finish the builds
- [ ] Merge the PR to the `main` branch

**Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.

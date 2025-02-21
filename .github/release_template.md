# Checklist for creating a new release

- [ ] Change version number in `docker/.version` and in `.env_template`
- [ ] Verify CI Tests
- [ ] Verify that the PR is named with a correct version number like x.x.x
- [ ] Merge the PR to the `main` branch. The release will be done automatically by the CI

**Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.
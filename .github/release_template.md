# Checklist for creating a new release

- [ ] Update `CHANGELOG.md` for the new version
- [ ] Change version number in `docs/source/schema.yml`, `docker/.version`
- [ ] Verify CI Tests
- [ ] Create release for the branch `develop`.
Write the following statement there (change the version number):

```commandline
please refer to the [Changelog](https://github.com/intelowlproject/GreedyBear/blob/develop/.github/CHANGELOG.md#v102)

WARNING: The release will be live within an hour!
```
- [ ] Wait for dockerHub [to finish the builds](https://hub.docker.com/repository/docker/intelowlproject/greedybear)
- [ ] Merge the PR to the `main` branch

**Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.
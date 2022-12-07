# Checklist for creating a new release

- [ ] Update `CHANGELOG.md` for the new version
- [ ] Change version number in `docs/source/conf.py`, `docs/source/schema.yml`, `greedybear/settings.py` and `docker/default.yml`
- [ ] Verify CI Tests
- [ ] Create release for the branch `develop`
- [ ] Wait for dockerHub [to finish the builds](https://hub.docker.com/repository/docker/intelowlproject/greedybear)
- [ ] Merge the PR to the `main` branch

**Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.


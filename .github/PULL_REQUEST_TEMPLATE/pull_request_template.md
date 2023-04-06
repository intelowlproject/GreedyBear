(Please add to the PR name the issue/s that this PR would close if merged by using a [Github](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) keyword. Example: `<feature name>. Closes #999`. If your PR is made by a single commit, please add that clause in the commit too. This is all required to automate the closure of related issues.)

# Description

Please include a summary of the change.

## Related issues
Please add related issues.

## Type of change

Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue).
- [ ] New feature (non-breaking change which adds functionality).
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected).

# Checklist

- [ ] I have read and understood the rules about [how to Contribute](https://greedybear.readthedocs.io/en/latest/Contribute.html) to this project.
- [ ] The pull request is for the branch `develop`.
- [ ] I have added documentation of the new features.
- [ ] Linters (`Black`, `Flake`, `Isort`) gave 0 errors. If you have correctly installed [pre-commit](https://greedybear.readthedocs.io/en/latest/Contribute.html#how-to-start-setup-project-and-development-instance), it does these checks and adjustments on your behalf.
- [ ] I have added tests for the feature/bug I solved. All the tests (new and old ones) gave 0 errors.
- [ ] If changes were made to an existing model/serializer/view, the docs were updated and regenerated (check [CONTRIBUTE.md](./Contribute.md)).
- [ ] If the GUI has been modified:
    - [ ] I have a provided a screenshot of the result in the PR.
    - [ ] I have created new frontend tests for the new component or updated existing ones.
  
### Important Rules
- If you miss to compile the Checklist properly, your PR won't be reviewed by the maintainers.
- If your changes decrease the overall tests coverage (you will know after the Codecov CI job is done), you should add the required tests to fix the problem
- Everytime you make changes to the PR and you think the work is done, you should explicitly ask for a review. After being reviewed and received a "change request", you should explicitly ask for a review again once you have made the requested changes.

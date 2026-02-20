# Description

Please include a short summary of the change. Don't just paste LLM output here.

### Related issues

Please add related issues: the issues you are trying to solve as well as other issues that are important in the context of this pull request.

### Type of change

- [ ] Bug fix (non-breaking change which fixes an issue).
- [ ] New feature (non-breaking change which adds functionality).
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected).
- [ ] Chore (refactoring, dependency updates, CI/CD changes, code cleanup, docs-only changes).

# Checklist

Please complete this checklist carefully. It helps guide your contribution and lets maintainers verify that all requirements are met.

### Formalities

- [ ] I have read and understood the rules about [how to Contribute](https://intelowlproject.github.io/docs/GreedyBear/Contribute/) to this project.
- [ ] I chose an appropriate title for the pull request in the form: `<feature name>. Closes #999`
- [ ] My branch is based on `develop`.
- [ ] The pull request is for the branch `develop`.
- [ ] I have reviewed and verified any LLM-generated code included in this PR.

### Docs and tests

- [ ] I documented my code changes with docstrings and/or comments.
- [ ] I have checked if my changes affect user-facing behavior that is described in the [docs](https://intelowlproject.github.io/docs/GreedyBear/). If so, I also created a pull request in the [docs repository](https://github.com/intelowlproject/docs).
- [ ] Linter (`Ruff`) gave 0 errors. If you have correctly installed [pre-commit](https://intelowlproject.github.io/docs/GreedyBear/Contribute/#how-to-start-setup-project-and-development-instance), it does these checks and adjustments on your behalf.
- [ ] I have added tests for the feature/bug I solved.
- [ ] All the tests gave 0 errors.

### GUI changes

Ignore this section if you did not make any changes to the GUI.

- [ ] I have provided a screenshot of the result in the PR.
- [ ] I have created new frontend tests for the new component or updated existing ones.
  
# Review process

- We encourage you to create a draft PR first, even when your changes are incomplete. This way you refine your code while we can track your progress and actively review and help.
- If you think your draft PR is ready to be reviewed by the maintainers, click the corresponding button. Your draft PR will become a real PR.
- If your changes decrease the overall tests coverage (you will know after the Codecov CI job is done), you should add the required tests to fix the problem.
- Every time you make changes to the PR and you think the work is done, you should explicitly ask for a review. After receiving a "change request", address the feedback and click "request re-review" next to the reviewer's profile picture at the top right.

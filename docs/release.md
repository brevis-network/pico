# Release Playbook

## Maintenance of two repos

We maintain two repos:

- **`brevis-vm`**: internal day-to-day development. The `brevis-vm` repo has release branches with the naming pattern `release/v1.0.x`. Everything in the release branches should be able to be made public immediately.
- **`pico`**: open source repo that mirrors the release branches of `brevis-vm`. The `pico` repo has exact copies of the latest code of all `brevis-vm` release branches, done through manual code drop-in (copy-paste) by our eng team members.

### Maintenance flow

As a rule of thumb, `brevis-vm` and `pico` repos should always have the same release branches (same branch names, same latest code, different git history). Usually, the person who makes the code changes should also be responsible for the repo sync.

#### From `brevis-vm` to `pico`
As we do our normal development in the `brevis-vm` repo, we update the latest or create a new release branch (with a regular PR and CI process) whenever we feel something new is ready to go public. Then, we copy-paste the new code to the `pico` repo and create a PR in the `pico` repo to update the branch with the same name.

In practice, it might be easier to copy-paste the entire repo (without `.git`), and overwrite the current code in the `pico` repo with the same branch name, and then double-check the code changes through `git diff`.

#### From `pico` to `brevis-vm`
If we accept a PR made by external developers in the `pico` repo, we should copy-paste the code changes back to `brevis-vm` repo.

## Release branches and tags

1. We use the standard version number scheme `a.b.c`, where `a` is the major version, `b` is the minor version, and `c` is the patch version. We are usually conservative in updating major version numbers. 
2. We maintain separate branches for each minor version, i.e., branch `release/v1.0.x`, and create release tags as needed. Frequent code updates can be made to a release branch, while official release tags are made less frequent.
3. To simplify the sync of two repos, the `main` branch of the `pico` repo should always have the same code as the latest release branch. An alternative approach is to maintain a `pico-main` branch in the `brevis-vm` repo, which we could try later if external contributions are frequent.
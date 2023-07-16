# Contributing to Xeol

The best way to find a good contribution to Xeol is to use it for something. If you find a bug or missing feature, that's a great place to start. If you have an idea for a new feature, that's also a great place to start. If you're not sure where to start, look at the [open issues](https://github.com/xeol-io/xeol/issues) and see if there's something that interests you.

You can ask questions along the way, we're always happy to help you with your contribution. For larger contributions, it's a good idea to open an issue first to discuss the change you want to make to make sure you're on the right track.

## GitHub Workflow

The recommended workflow is to fork the repository and open pull requests from your fork.

### 1. Fork, clone & configure Xeol upstream
- Click on the Fork button on GitHub
- Clone your fork
- Add the upstream repository as a new remote

```shell
# Clone repository
git clone https://github.com/$YOUR_GITHUB_USER/$REPOSITORY.git

# Add upstream origin
git remote add upstream git@github.com:xeol-io/$REPOSITORY.git
```

### 2. Create a pull request

```shell
# Create a new feature branch
git checkout -b my_feature_branch

# Make changes to your branch
# ...

# Commit changes - remember to sign!
git commit -s

# Push your new feature branch
git push my_feature_branch

# Create a new pull request from https://github.com/xeol-io/$REPOSITORY
```

### 3. Update your pull request with latest changes

```shell
# Checkout main branch
git checkout main

# Update your fork's main branch from upstream
git pull upstream main

# Checkout your feature branch
git checkout my_feature_branch

# Rebase your feature branch changes on top of the updated main branch
git rebase main

# Update your pull request with latest changes
git push -f my_feature_branch
```

## Adding a feature or fix

If you look at the Xeol [Issue](https://github.com/xeol-io/xeol/issues) you can look at the [good first issue](https://github.com/xeol-io/xeol/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22) list if you're not sure where to start.

# Commits

## DCO

Contributions to this project must be accompanied by a Developer Certificate of Origin (DCO).

All commit messages must contain the Signed-off-by line with an email address that matches the commit author.

The `sign-off` line must match the author's real name, otherwise the PR will be rejected. The `sign-off` is an added line at the end of the explanation for the commit, certifying that you wrote it or otherwise have the right to submit it as an open-source patch. By submitting a contribution, you agree to be bound by the terms of the DCO Version 1.1 and Apache License Version 2.0.

Signing off a commit certifies the below Developer's Certificate of Origin (DCO):

```text
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

   (a) The contribution was created in whole or in part by me and I
       have the right to submit it under the open source license
       indicated in the file; or

   (b) The contribution is based upon previous work that, to the best
       of my knowledge, is covered under an appropriate open source
       license and I have the right under that license to submit that
       work with modifications, whether created in whole or in part
       by me, under the same open source license (unless I am
       permitted to submit under a different license), as indicated
       in the file; or

   (c) The contribution was provided directly to me by some other
       person who certified (a), (b) or (c) and I have not modified
       it.

   (d) I understand and agree that this project and the contribution
       are public and that a record of the contribution (including all
       personal information I submit with it, including my sign-off) is
       maintained indefinitely and may be redistributed consistent with
       this project or the open source license(s) involved.
```

All contributions to this project are licensed under the [Apache License Version 2.0, January 2004](http://www.apache.org/licenses/).

When committing your change, you can add the required line manually so that it looks like this:

```text
Signed-off-by: John Doe <john.doe@example.com>
```

Alternatively, configure your Git client with your name and email to use the `-s` flag when creating a commit:

```text
$ git config --global user.name "John Doe"
$ git config --global user.email "john.doe@example.com"
```

Creating a signed-off commit is then possible with `-s` or `--signoff`:

```text
$ git commit -s -m "this is a commit message"
```

To double-check if the commit was signed-off, look at the log output:

```text
$ git log -1
commit 37ceh170e4hb283bb73d958f2036ee5k07e7fde7 (HEAD -> issue-35, origin/main, main)
Author: John Doe <john.doe@example.com>
Date:   Mon Aug 1 11:27:13 2020 -0400

    this is a commit message

    Signed-off-by: John Doe <john.doe@example.com>
```

## Test your changes

This project has a `Makefile` which includes many helpers running both unit and integration tests. Although PRs will have automatic checks for these, it is useful to run them locally, ensuring they pass before submitting changes. Ensure you've bootstrapped once before running tests:

```text
$ make bootstrap
```

You only need to bootstrap once. After the bootstrap process, you can run the tests as many times as needed:

```text
$ make unit
$ make integration
```

You can also run `make all` to run a more extensive test suite, but there is additional configuration that will be needed for those tests to run correctly. We will not cover the extra steps here.

## Pull Request

If you made it this far and all the tests are passing, it's time to submit a Pull Request (PR) for Xeol. Submitting a PR is always a scary moment as what happens next can be an unknown. The Xeol project strives to be easy to work with, we appreciate all contributions. Nobody is going to yell at you or try to make you feel bad. We love contributions and know how scary that first PR can be.


## Security Vulnerabilities

Found a security vulnerability? See in our [Security Policy](SECURITY.md) to see how to report it to be solved as soon as possible.

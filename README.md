# Uptane Standard

[Uptane](https://uptane.github.io) is the first compromise-resilient software update security system for the automotive industry. In 2018, a working group began the process of describing the system's design, implementation, and deployment considerations as a formal standard. Working as an [IEEE-ISTO](https://ieee-isto.org/) industry group, Volume 1.0.0 of *IEEE/ISTO#6100.1.0.0: Uptane Standard for Design and Implementation* was released in July 2019. The Uptane standards initiative is now under the umbrella of the [Linux Foundation Joint Development Foundation](http://www.jointdevelopment.org/). This repository is the public home of that standardization work.

## Existing documentation

Several documents are already available which describe Uptane's design and implementation. Note that *Uptane Standard for Design and Implementation* should be considered the authoritative resource for the framework:

* [Uptane Standards Document V. 1.0.0](https://uptane.github.io/uptane-standard/uptane-standard.html)
* [Reference Implementation and Demonstration Code](https://github.com/uptane/uptane)

## Contributing

The Standard is being written in [RFC 2629](https://tools.ietf.org/html/rfc2629)/[RFC 7749](https://tools.ietf.org/html/rfc7749) format, using Markdown as a source. Comments, issues, and pull requests are welcome.

We use [GitHub Flow](https://guides.github.com/introduction/flow/) for contributing content. To work on a section, make a branch off the current master, and submit a pull request when it's ready to merge. If GitHub reports any merge conflicts in the PR, please rebase until the merge can be done cleanly.

### Commit messages and squashes

Use clear, informative commit messages, and squash any minor commits that do not represent an actual contribution of content (e.g. typo fixes). It is not necessary to squash all your commits when submitting a PR, but please try to keep the commit history reasonably clean.

### Text formatting

Don't use fixed-width columns. The `plaintext` rendering target will produce a text file with fixed-width columns; using fixed-width columns in the markdown source just makes the diffs harder to read.

## Building/rendering the document

We use [kramdown-rfc2629](https://github.com/cabo/kramdown-rfc2629) to render the markdown source into xml, and [xml2rfc](https://xml2rfc.tools.ietf.org/) to render the XML into HTML or plaintext. A Makefile is included for convenience. You can also render using [Docker](https://www.docker.com/) if you don't wish to install the tools. See `make help` for options.

### Pushing to GitHub pages

The rendered HTML from the markdown source at `master` will be available at https://uptane.github.io/uptane-standard/uptane-standard.html. You can update this, if you have commit rights to this repository, by pushing `uptane-standard.html` to the `gh-pages` branch.

TODO: Set up CI to auto-push on merge to master.

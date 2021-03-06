# Uptane Standard

[Uptane](https://uptane.github.io) is the first compromise-resilient software update security system for the automotive industry. In 2018, a working group under [IEEE-ISTO](https://ieee-isto.org/) began the process of describing the system's design, implementation, and deployment as a formal standard. On July 31, 2019 IEEE/ISTO released *IEEE-ISTO 6100.1.0.0: Uptane Standard for Design and Implementation* (see link below under documentation). Uptane is now a [Linux Foundation Joint Development Foundation](http://www.jointdevelopment.org/) project, and released [version 1.1.0](https://uptane.github.io/papers/uptane-standard.1.1.0.html) of the Uptane Standard for Design and Implementation on January 8, 2021.

This repository is the public home of all standardization work for Uptane.

## Existing documentation

The Uptane Standards document should be considered the authoritative resource for the framework. Several other documents and materials are available or currently in development. The information in all of these other guidelines should be viewed as complementary to the official Uptane Standard, and as recommendations rather than mandatory instructions. 

* [Uptane Standard v.1.1.0](https://uptane.github.io/papers/uptane-standard.1.1.0.html)
* [Reference Implementation and Demonstration Code](https://github.com/uptane/uptane)
* [Deployment Best Practices](https://uptane.github.io/deployment-considerations/index.html)
* [Uptane POUF (Protocols, Operations, Usage, and Formats) Guidelines](https://uptane.github.io/pouf.html)
* [Example POUF](https://uptane.github.io/reference_pouf.html)

## Contributing

The standard is being written in [RFC 2629](https://tools.ietf.org/html/rfc2629)/[RFC 7749](https://tools.ietf.org/html/rfc7749) format, using Markdown as a source. Comments, issues, and pull requests are welcome.

We use [GitHub Flow](https://guides.github.com/introduction/flow/) for contributing content. When you are working on a section, make a branch off the current master, and submit a pull request when it's ready to merge. If GitHub reports any merge conflicts in the PR, please rebase until the merge can be done cleanly.

### Commit messages and squashes

Use clear, informative commit messages, and squash any minor commits that do not represent an actual contribution of content (e.g. typo fixes). It is not necessary to squash all your commits when submitting a PR, but please try to keep the commit history reasonably clean.

### Text formatting

Don't use fixed-width columns. The `plaintext` rendering target will produce a text file with fixed-width columns; using fixed-width columns in the Markdown source just makes the diffs harder to read.

### Style guide

Capitalize proper nouns and titles of things, such as the names of roles, repositories, and specific types of metadata. Do not capitalize the words role, repository, and metadata, however. For example, write "Targets role" and "Director repository."

For headings and sub-headings, capitalize only the first word in a heading UNLESS the heading contains a proper noun.

Do not hyphenate the adjectival phrase "partial verification Secondary".

Use American English spellings (i.e. write "color" instead of "colour" and "artifacts" instead of "artefacts").

Links to the Standard (from outside the Standard) should point to the latest rendered released version. It is preferred to link by section name, not number, as the numbers tend to change more than the names. Internal links within the Standard should use the standard cross-link syntax.

Links to the Deployment Best Practices should point to the [deployed web pages](https://uptane.github.io/deployment-considerations/index.html).

## Building/rendering the document

We use [kramdown-rfc2629](https://github.com/cabo/kramdown-rfc2629) to render the Markdown source into xml, and [xml2rfc](https://xml2rfc.tools.ietf.org/) to render the XML into HTML or plaintext. A Makefile is included for convenience. You can also render using [Docker](https://www.docker.com/) if you don't wish to install the tools. See `make help` for options.

### Pushing to GitHub pages

The rendered HTML from the markdown source at `master` will be available at https://uptane.github.io/uptane-standard/uptane-standard.html. You can update this, if you have commit rights to this repository, by pushing `uptane-standard.html` to the `gh-pages` branch.

TODO: Set up CI to auto-push on merge to master.

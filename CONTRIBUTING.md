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

When referring to actions in the Standard that require compliance, the word SHALL will be used, rather than the word MUST.

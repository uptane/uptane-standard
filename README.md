# Uptane Standard

[Uptane](https://uptane.github.io) is the first compromise-resilient software update security system for the automotive industry. In 2018, a working group under [IEEE-ISTO](https://ieee-isto.org/) began the process of describing the system's design, implementation, and deployment as a formal standard. On July 31, 2019 IEEE/ISTO released *IEEE-ISTO 6100.1.0.0: Uptane Standard for Design and Implementation* (see link below under documentation). Uptane is now a [Linux Foundation Joint Development Foundation](http://www.jointdevelopment.org/) project. The most recent version of the Standard [version 2.1.0](https://uptane.github.io/uptane-standard/2.1.0/uptane-standard.html) was released on June 27, 2023.

This repository is the public home of all standardization work for Uptane.

As the Standard is a living document, updates are made in real time as needed. However, these changes will not be considered formally adopted until the release of the next minor or major version.

Major and minor release dates are set by the Uptane Standards committee. All final releases will be approved by the committee, either by voice vote at a designated bimonthly meeting of the Uptane Standard group or by responding "approve" in a designated mailing list or repository thread. A release will be deemed approved if it receives a simple majority of positive responses by active group members. "Active" here is defined as an individual who regularly appears at bimonthly meetings, or participates in the preparation or review of pull requests, or engages in discussion of issues on the mailing list threads. Upcoming votes will be announced at least two weeks prior to taking or finalizing votes.

## Existing documentation

The Uptane Standards document should be considered the authoritative resource for the framework. Several other documents and materials are available or currently in development. The information in all of these other guidelines should be viewed as complementary to the official Uptane Standard, and as recommendations rather than mandatory instructions.

* [Uptane Standard v.2.1.0](https://uptane.github.io/uptane-standard/2.1.0/uptane-standard.html
* [Deployment Best Practices v.2.0.0](https://uptane.github.io/papers/V2.0.0_uptane_deploy.html)
* [Uptane POUF (Protocols, Operations, Usage, and Formats) Guidelines](https://uptane.github.io/pouf.html)
* [Example POUF](https://uptane.github.io/reference_pouf.html)

## Building/rendering the document

We use [kramdown-rfc2629](https://github.com/cabo/kramdown-rfc2629) to render the Markdown source into xml, and [xml2rfc](https://xml2rfc.tools.ietf.org/) to render the XML into HTML or plaintext. A Makefile is included for convenience. You can also render using [Docker](https://www.docker.com/) if you don't wish to install the tools. See `make help` for options.

### Pushing to GitHub pages

The rendered HTML from the markdown source at `master` will be available at https://uptane.github.io/uptane-standard/uptane-standard.html. You can update this, if you have commit rights to this repository, by pushing `uptane-standard.html` to the `gh-pages` branch.

TODO: Set up CI to auto-push on merge to master.

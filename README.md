# Uptane IEEE-ISTO Standard

[Uptane](https://uptane.github.io) is the first compromise-resilient software update security system for the automotive industry. Beginning in 2018, a working group has begun the process of describing the system's design, implementation, and deployment considerations as a formal standard. This repository is the public home of that standardization work.

## Existing documentation

Several documents are already available which describe Uptane's design and implementation:

* [Design Overview](https://docs.google.com/document/d/1pBK--40BCg_ofww4GES0weYFB6tZRedAjUy6PJ4Rgzk/edit?usp=sharing)
* [Implementation Specification](https://docs.google.com/document/d/1wjg3hl0iDLNh7jIRaHl3IXhwm0ssOtDje5NemyTBcaw/edit?usp=sharing)
* [Deployment Considerations](https://docs.google.com/document/d/17wOs-T7mugwte5_Dt-KLGMsp-3_yAARejpFmrAMefSE/edit?usp=sharing)
* [Reference Implementation and Demonstration Code](https://github.com/uptane/uptane)

## Contributing

The standard is being written in [RFC 2629](https://tools.ietf.org/html/rfc2629)/[RFC 7749](https://tools.ietf.org/html/rfc7749) format, using markdown as a source. Comments, issues, and pull requests are welcome.

## Building/rendering the document

We use [kramdown-rfc2629](https://github.com/cabo/kramdown-rfc2629) to render the markdown source into xml, and [xml2rfc](https://xml2rfc.tools.ietf.org/) to render the XML into HTML or plaintext. A Makefile is included for convenience. You can also render using [Docker](https://www.docker.com/) if you don't wish to install the tools. See `make help` for options.


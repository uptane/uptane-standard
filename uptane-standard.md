---
title: Uptane IEEE-ISTO Standard for Design and Implementation
abbrev: UPTANE
docname: uptane-standard-design
date: 2018-08-28
category: info

ipr: noDerivativesTrust200902
area: TODO
workgroup: TODO
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - ins: J. Cappos
    name: Justin Cappos
    organization: NYU Tandon School of Engineering
    email: redacted@nyu.edu
    street: todo
    country: USA
    region: NY
    city: New York
    code: todo

normative:
  # Keyword def (MUST, SHALL, MAY, etc.)
  RFC2119:
  # HTTP/1.1
  RFC2616:
  # X.509
  RFC3280:
  # PKCS:RSA
  RFC3447:
  # SHA
  RFC4634:
  # base64
  RFC4648:
  # RSA updates
  RFC5756:
  # JSON
  RFC7159:

informative:
  # MD5
  RFC1321:
  ED25519:
    title: '"High-Speed High-Security Signatures", Journal of Cryptographic Engineering, Vol. 2'
    author:
      - ins: D. J. Bernstein
      - ins: N. Duif
      - ins: T. Lange
      - ins: P. Schwabe
      - ins: B-Y. Yang
    date: 2011-09-26
  MERCURY:
    # TODO
    title: https://ssl.engineering.nyu.edu/papers/kuppusamy_usenix_17.pdf
    author:
      - ins: Kuppusamy
    date: 2017-01-01
  # TODO add TUF
  # TODO add DER

--- abstract

This document describes a framework for securing automotive software update systems.

--- middle


# Introduction

TODO

# Terminology

## Conformance Terminology

## Automotive Terminology

## Uptane Role Terminology

## Acronyms and Abbreviation

# Requirements for Uptane

## Rationale

## Use Cases

## Exceptions

## Out of Scope

## Design Requirements

# Detailed Design of Uptane

## Repositories and Servers

### Image Repository

### Director Repository

### Time Server

## Primary vs. Secondary Verification

## Roles

In order to read and write metadata, it helps to understand that all metadata on
a repository is produced by one of four basic roles: root, targets, snapshot,
and timestamp. The relationships between these roles are illustrated in Figure
2a, whereas Table 2a summarizes their respective responsibilities. To better
understand the design behind these roles, the reader should read the
[CCS’10 paper](https://ssl.engineering.nyu.edu/papers/samuel_tuf_ccs_2010.pdf)
on The Update Framework (TUF), a precursor to Uptane.

Figure 2a: The four basic (root, timestamp, snapshot, and targets) roles used
in Uptane, along with the corresponding metadata and images.

Table 2a: The four basic roles that Uptane uses to add signed metadata to a
repository.

### The Root Role

The root role serves as the certificate authority. It distributes and revokes
the public keys used to verify metadata produced by each of the four basic roles
(including itself).

### The Targets Role and Delegations

The targets role provides metadata, such as hashes and file sizes, about images.

Instead of signing metadata itself, the targets role MAY delegate the
responsibility of signing this metadata to other, custom-made roles. For
example, in Figure 2a, the targets role has delegated all images that match the
filename pattern “A.*” to the A1 role, and all images that match the filename
patterns “B.*” and “C.*” to the BC role. In turn, the A1 role delegates a subset
of its images (in this case, only the “A.img”) to the A2 role. A delegation
binds the public keys used by a delegatee to a subset of the images these keys
are trusted to sign. This means that the targets role distributes and revokes
the public keys for the A1 and BC roles, whereas the A1 role does the same for
the A2 role.

There are two types of delegations: prioritized and / or terminating
delegations. Furthermore, a delegation may require multiple roles, as explained
below.

#### Prioritized Delegations

Sometimes an image may be delegated to more than one role. For example, the
targets role could delegate all images to both A1 and BC. In this case, if both
A1 and BC sign metadata about the same image, it may be unclear to a client
which role should be trusted. In order to solve this problem, all delegations in
Uptane are prioritized. Returning to the example, the targets role lists its
delegations such that A1 is prioritized over BC. Thus, if A1 signs metadata
about some image, its metadata is trusted over BC. For more information, the
reader should read the
[NSDI’16 paper](https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/kuppusamy)
on prioritized and terminating delegations.

#### Terminating Delegations

In other cases, it is desirable for a role X to delegate an image to role Y such
that, if Y (or any of its own delegations) has not signed any metadata about the
image, then the client SHALL NOT search the rest of the delegations in role X
for this image. Using a terminating delegation from X to Y lets X endow this
delegation with precisely this meaning. In Uptane, delegations SHOULD NOT be
terminating by default, unless stated otherwise. For more information, the
reader should read the
[NSDI’16 paper](https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/kuppusamy)
on prioritized and terminating delegations.

#### Multi-Role Delegation

There may be occasions where multiple roles may be required to sign the same
metadata about the same image. For example, a supplier may require both its
development and release engineering teams to sign off on all images. Using
multi-role delegations, the supplier delegates all images to a combination of
its development and release engineering roles, so that a client installs an
image only if both roles have signed the same metadata about it. For more
information, the reader should read
[TAP 3](https://github.com/theupdateframework/taps/blob/master/tap3.md).

### Delegated Targets Roles

Although the targets role is necessary, Uptane does not force any particular
model of delegations on an OEM. The
[Deployment Considerations](https://docs.google.com/document/d/17wOs-T7mugwte5_Dt-KLGMsp-3_yAARejpFmrAMefSE/edit?usp=sharing)
document discusses some useful models for delegations in deployment scenarios.

#### The Supplier Roles

An OEM MAY use the targets role to delegate the signing of images for an ECU to
the supplier that develops and maintains those images. There MAY be as many of
these roles as there are suppliers.

### The Snapshot Role

The snapshot role indicates which images have been released by the repository at
the same time. It does so indirectly, by signing metadata about all targets
metadata files released by the repository at the same time.

### The Timestamp Role

The timestamp role indicates whether there are any new metadata or images on the
repository. It does so indirectly, by signing metadata about the snapshot
metadata file.

### The Map File

The OEM SHALL use the map file to specify that all images must be signed by both
the image and director repositories. As discussed in Section A.2 of the
[Deployment Considerations](https://docs.google.com/document/d/17wOs-T7mugwte5_Dt-KLGMsp-3_yAARejpFmrAMefSE/edit?usp=sharing)
 document, every primary and full verification secondary is supplied with a copy
 of this map file during manufacture. The contents of this file is specified in
 Section X of this document. For more information about the map file, the
 reader should read TAP 4.

# Metadata

## Common Metadata Structures and Formats

## Root Metadata

## Targets Metadata

### Metadata about Images

### Metadata about Delegations

### Example: Targets Metadata on Image and Director Repositories

### Snapshot Metadata

### Timestamp Metadata

### Filename Conventions for Metadata or ECUs vs. repositories

### The Map File

### Repository Tools for Writing Metadata

# Image Repository

# Director Repository

## Directing Installation of Images on Vehicles

## Inventory Database

# Time server

# Downloading, verifying, and installing updates on the vehicle

## Primary ECU Download Process Overview, including Verification and Distribution to Secondaries

## How an ECU Installs a New Image

## How an ECU Verifies Metadata

### Partial Verification

### Full Verification

## Notes about Implementation Details

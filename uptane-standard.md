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

### The Root Role

### The Targets Role and Delegations

#### Prioritized Delegations

#### Terminating Delegations

#### Multi-Role Delegation

### Delegated Targets Roles

#### The Supplier Roles

### The Snapshot Role

### The Timestamp Role

### The Map File

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


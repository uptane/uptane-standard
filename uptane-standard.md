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
  # X.509 PKI spec
  RFC3647:
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

Uptane is a secure software update framework for automobiles. We do not specify implementation details. Instead, we describe the components necessary for a compliant implementation, and leave it up to individual implementors to make their own technological choices within those requirements.

At a high level, Uptane requires:

* Two software repositories:
    * An image repository containing binary images for install, and signed metadata about those images
    * A director repository connected to an inventory database that can sign metadata on demand for images in the image repository
* Repository tools for generating Uptane-specific metadata about images
* A public key infrastructure supporting the required metadata production/signing roles on each repository:
    * Root - Certificate authority for the repo. Distributes public keys for verifying all the other roles' metadata
    * Timestamp - Indicates whether there are new metadata or images
    * Snapshot - Indicates images released by the repository at a point in time, via signing metadata about targets metadata
    * Targets - Indicates metadata about images, such as hashes and file sizes
* A time server to deliver cryptographically verifiable time to ECUs
* An in-vehicle client on a primary ECU capable of verifying the signatures on all update metadata, handling all server communication, and downloading updates on behalf of secondary ECUs
* A client or library on each secondary ECU capable of performing either full or partial verification of metadata

## Roles on repositories {#roles}

A repository contains images and metadata. Each role has a particular type of metadata associated with it, as described in {{meta_syntax}}.

### The Root role {#root_role}

The Root role SHALL be responsible for a Certificate Authority as defined in {{RFC3647}}.
The Root role SHALL produce and sign Root metadata as described in {{root_meta}}.
The Root role SHALL sign the public keys used to verfy the metadata produced by the Timestamp, Snapshot, and Targets roles.
The Root role SHALL revoke keys for the other roles, in case of compromise.

### The Targets role {#targets_role}

The Targets role SHALL produce and sign metadata about images and delegations as described in {{targets_meta}}.

#### Delegations

The Targets role on the Image repository MAY delegate the responsibility of signing metadata to other, custom-defined roles. If it does, it MUST do so as specified in {{delegations_meta}}.

Responsibility for signing images or a subset of images MAY be delegated to more than one role, and therefore it is possible for two different roles to be trusted for signing a particular image. For this reason, delegations MUST be prioritized.

A particular delegation for a subset of images MAY be designated as **terminating**. For terminating delegations, the client SHALL NOT search the any further if it does not find validly signed metadata about those images in the terminating delegation. Delegations SHOULD NOT be terminating by default; terminating delegations SHOULD only be used when there is a compelling technical reason to do so.

A delegation for a subset of images MAY be a multi-role delegation. A multi-role delegation indicates that each of the delegatee roles MUST sign the same metadata.

Delegations only apply to the Image repository. The Targets role on the Director repository MUST NOT delegate metadata signing responsibility.

### The Snapshot role {#snapshot_role}

The Snapshot role SHALL produce and sign metadata about all Targets metadata the repository releases, including the current version number and hash of the main Targets metadata and the version numbers and hashes of all delegated targets metadata, as described in {{snapshot_meta}}.

### The Timestamp role {#timestamp_role}

The Timestamp role SHALL produce and sign metadata indicating whether there are new metadata or images on the repository. It MUST do so by signing the metadata about the Snapshot metadata file.

## Metadata abstract syntax {#meta_syntax}

### Common Metadata Structures and Formats

### Root Metadata {#root_meta}

### Targets Metadata {#targets_meta}

#### Metadata about Images

#### Metadata about Delegations {#delegations_meta}

### Snapshot Metadata {#snapshot_meta}

### Timestamp Metadata {#timestamp_meta}

## Server / repository implementation requirements

An Uptane implementation SHALL make the following services available to vehicles:

* Image repository
* Director repository
* Time server

### Image Repository

The Image repository exists to allow an OEM and/or its suppliers to upload images and their associated metadata. It makes these images and their metadata available to vehicles. The Image repository is designed to be primarily controlled by human actors, and updated relatively infrequently.

The Image repository SHALL expose an interface permitting the download of metadata and images. This interface SHOULD be public.

The Image repository SHALL require authorization for writing metadata and images.

The Image repository SHALL provide a method for authorized users to upload images and their associated metadata. It SHALL check that a user writing metadata and images is authorized to do so for that specific image by checking the chain of delegations for the image as described in {{delegations_meta}}.

The Image repository SHALL implement storage which permits authorized users to write an image file using a unique filename, and later read the same file using the same name. It MAY use any filesystem, key-value store, or database that fulfills this requirement.

The Image repository MAY require authentication for read access.

### Director Repository

The Director repository instructs ECUs as to which images should be installed by producing signed metadata on demand. Unlike the Image repository, it is mostly controlled by automated, online processes. It also consults a private inventory database containing information on vehicles, ECUs, and software revisions.

The Directory repository SHALL expose an interface for primaries to upload vehicle version manifests and download metadata. This interface SHOULD be public.
The Director MAY encrypt images for ECUs that require it, either by encrypting on-the-fly or by storing encrypted images in the repository.

The Director repository SHALL implement storage which permits an automated service to write generated metadata files. It MAY use any filesystem, key-value store, or database that fulfills this requirement.

#### Directing installation of images on vehicles

A Director repository MUST conform to the following six-step process for directing the installation of software images on a vehicle.

1. When the Director receives a vehicle version manifest sent by a primary (as described in {{construct_manifest}}), it decodes the manifest, and determines the unique vehicle identifier.
1. Using the vehicle identifier, the Director queries its inventory database (as described in {{inventory_db}}) for relevant information about each ECU in the vehicle.
1. The Director checks the manifest for accuracy compared to the information in the inventory database. If any of the required checks fail, the Director drops the request. An implementor MAY make whatever additional checks they wish. At a minimum, the following checks are required:
    * Each ECU recorded in the inventory database is also represented in the manifest.
    * The signature of the manifest matches the ECU key of the primary that sent it.
    * The signature of each secondary's contribution to the manifest matches the ECU key of that secondary.
1. The Director extracts information about currently installed images from the vehicle version manifest. Using this information, it determines if the vehicle is already up-to-date, and if not, determines a set of images that should be installed. The exact process by which this determination takes place is out of scope of this standard. However, it MUST take into account *dependencies* and *conflicts* between images, and SHOULD consult well-established techniques for dependency resolution.
1. The Director MAY encrypt images for ECUs that require it.
1. The Director generates new metadata representing the desired set of images to be installed in the vehicle, based on the dependency resolution in step 4. This includes targets ({{targets_meta}}), snapshot ({{snapshot_meta}}), and timestamp ({{timestamp_meta}}) metadata. It then sends this metadata to the primary as described in {{download_meta}}.

#### Inventory Database {#inventory_db}

The Director SHALL use a private inventory database to store information about ECUs and vehicles. An implementor MAY use any durable database for this purpose.

The inventory database MUST record the following pieces of information:

* Per vehicle:
    * A unique identifier (such as a VIN)
* Per ECU:
    * A unique identifier (such as a serial number)
    * The vehicle identifier the ECU is associated with
    * A public key
    * The format of the public key
    * Whether the ECU is a primary or a secondary

The inventory database MAY record other information about ECUs and vehicles.

### Time Server

The Time Server exists to inform vehicles about the current time in cryptographically secure way, since many ECUs in a vehicle will not have a reliable source of time. It receives lists of tokens from vehicles, and returns back a signed sequence that includes the token and the current time.

The Time Server SHALL receive a sequence of tokens from a vehicle representing all of its ECUs. In response, it SHALL sign each token together with the current time.

The Time Server SHALL expose a public interface allowing primaries to communicate with it. This communication MAY occur over FTP, FTPS, SFTP, HTTP, or HTTPS.

## In-vehicle implementation requirements

### Downloading and distributing updates on a primary ECU

#### Construct and send vehicle version manifest {#construct_manifest}

#### Download and check current time {#check_time}

#### Download and verify metadata {#download_meta}

#### Download and verify images

#### Send latest time to secondaries

#### Send metadata to secondaries

#### Send images to secondaries

### Installing images on ECUs

### Metadata verification

#### Full verification

#### Partial verification



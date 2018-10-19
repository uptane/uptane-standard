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
  # TAP 4 at rev 2cb67d9
  TAP-4:
    target: https://github.com/theupdateframework/taps/commit/2cb67d913ec19424d1e354b38f862886fbfd4105
    title: The Update Framework TAP 4 - Multiple repository consensus on entrusted targets
    author:
      - ins: T.K. Kuppusamy
      - ins: S. Awwad
      - ins: E. Cordell
      - ins: V. Diaz
      - ins: J. Moshenko
      - ins: J. Cappos
    date: 2017-12-15
  # TAP 5 at rev 01726d2
  TAP-5:
    target: https://github.com/theupdateframework/taps/blob/01726d203c9b9c029d26f6612069ce3180500d9a/tap5.md#downloading-metadata-and-target-files
    title: The Update Framework TAP 5 - Setting URLs for roles in the root metadata file
    author:
      - ins: T.K. Kuppusamy
      - ins: S. Awwad
      - ins: E. Cordell
      - ins: V. Diaz
      - ins: J. Moshenko
      - ins: J. Cappos
    date: 2018-01-22

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
    target: https://www.usenix.org/system/files/conference/atc17/atc17-kuppusamy.pdf
    title: "Mercury: Bandwidth-Effective Prevention of Rollback Attacks Against Community Repositories"
    author:
      - ins: T.K. Kuppusamy
      - ins: V. Diaz
      - ins: J. Cappos
    seriesinfo:
      ISBN: 978-1-931971-38-6
    date: 2017-07-12
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

### The map file {#map_file}

### Rules for filenames in repositories and metadata {#metadata_filename_rules}

### Vehicle version manifest {#vehicle_version_manifest}

#### ECU version report {#version_report}

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

The Directory repository SHALL expose an interface for primaries to upload vehicle version manifests ({{vehicle_version_manifest}}) and download metadata. This interface SHOULD be public.
The Director MAY encrypt images for ECUs that require it, either by encrypting on-the-fly or by storing encrypted images in the repository.

The Director repository SHALL implement storage which permits an automated service to write generated metadata files. It MAY use any filesystem, key-value store, or database that fulfills this requirement.

#### Directing installation of images on vehicles

A Director repository MUST conform to the following six-step process for directing the installation of software images on a vehicle.

1. When the Director receives a vehicle version manifest sent by a primary (as described in {{construct_manifest_primary}}), it decodes the manifest, and determines the unique vehicle identifier.
1. Using the vehicle identifier, the Director queries its inventory database (as described in {{inventory_db}}) for relevant information about each ECU in the vehicle.
1. The Director checks the manifest for accuracy compared to the information in the inventory database. If any of the required checks fail, the Director drops the request. An implementor MAY make whatever additional checks they wish. At a minimum, the following checks are required:
    * Each ECU recorded in the inventory database is also represented in the manifest.
    * The signature of the manifest matches the ECU key of the primary that sent it.
    * The signature of each secondary's contribution to the manifest matches the ECU key of that secondary.
1. The Director extracts information about currently installed images from the vehicle version manifest. Using this information, it determines if the vehicle is already up-to-date, and if not, determines a set of images that should be installed. The exact process by which this determination takes place is out of scope of this standard. However, it MUST take into account *dependencies* and *conflicts* between images, and SHOULD consult well-established techniques for dependency resolution.
1. The Director MAY encrypt images for ECUs that require it.
1. The Director generates new metadata representing the desired set of images to be installed in the vehicle, based on the dependency resolution in step 4. This includes targets ({{targets_meta}}), snapshot ({{snapshot_meta}}), and timestamp ({{timestamp_meta}}) metadata. It then sends this metadata to the primary as described in {{download_meta_primary}}.

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

### Time Server {#time_server}

The Time Server exists to inform vehicles about the current time in cryptographically secure way, since many ECUs in a vehicle will not have a reliable source of time. It receives lists of tokens from vehicles, and returns back a signed sequence that includes the token and the current time.

The Time Server SHALL receive a sequence of tokens from a vehicle representing all of its ECUs. In response, it SHALL sign each token together with the current time.

The Time Server SHALL expose a public interface allowing primaries to communicate with it. This communication MAY occur over FTP, FTPS, SFTP, HTTP, or HTTPS.

## In-vehicle implementation requirements

An Uptane-compliant ECU SHALL be able to download and verify the time, metadata, and image binaries before installing a new image.

Each ECU in a vehicle receiving over-the-air updates is either a primary or a secondary ECU. A primary ECU collects and delivers to the Director vehicle manifests ({{vehicle_version_manifest}}) containing information about which images have been installed on ECUs in the vehicle. It also downloads and verifies the latest time, metadata, and images for itself and for its secondaries. A secondary ECU downloads and verifies the latest time, metadata, and images for itself from its associated primary ECU. It also sends signed information about its installed images to its associated primary.

All ECUs MUST verify image metadata as specified in {{metadata_verification}} before installing an image or making it available to other ECUs. A primary ECU MUST perform full verification ({{full_verification}}). A secondary ECU SHOULD perform full verification if possible, and MUST perform full verification if it is safety-critical. If it is not safety-critical, it MAY perform partial verification ({{partial_verification}}) instead.

### Build-time prerequisite requirements for ECUs

For an ECU to be capable of receiving Uptane-secured updates, it MUST have the following data provisioned at the time it is manufactured or installed in the vehicle:

1. The latest copy of required Uptane metadata at the time of manufacture or install.
    * Partial verification ECUs MUST have the root and targets metadata from the director repository.
    * Full verification ECUs MUST have a complete set of metadata from both repositories (root, targets, snapshot, and timestamp), as well as the repository map file.
2. The public key(s) of the time server.
3. An attestation of time downloaded from the time server.
4. An **ECU key**. This is a private key, unique to the ECU, used to sign ECU version manifests and decrypt images. An ECU key MAY be either a symmetric key or an asymmetric key. If it is an asymmetric key, there MAY be separate keys for encryption and signing. For the purposes of this standard, the set of private keys that an ECU uses is referred to as the ECU key (singular), even if it is actually multiple keys used for different purposes.

### Downloading and distributing updates on a primary ECU

A primary downloads, verifies, and distributes the latest time, metadata and images. To do so, it SHALL perform the following seven steps:

1. Construct and send vehicle version manifest ({{construct_manifest_primary}})
1. Download and check current time ({{check_time_primary}})
1. Download and verify metadata ({{download_meta_primary}})
1. Download and verify images ({{download_images_primary}})
1. Send latest time to secondaries ({{send_time_primary}})
1. Send metadata to secondaries ({{send_metadata_primary}})
1. Send images to secondaries ({{send_images_primary}})


#### Construct and send vehicle version manifest {#construct_manifest_primary}

The primary SHALL build a *vehicle version manifest* as described in {{vehicle_version_manifest}}.

Once it has the complete manifest built, it MAY send the manifest to the director repository. However, it is not strictly required that the primary send the manifest until step three.

Secondaries MAY send their version report at any time, so that it is stored on the primary already when it wishes to check for updates. Alternatively, the Primary MAY request a version report from each secondary at the time of the update check.

#### Download and check current time {#check_time_primary}

The primary SHALL download the current time from the time server, for distribution to its secondaries.

The version report from each secondary ECU (as described in {{version_report}}) contains a nonce, plus a signed ECU version report. The primary SHALL gather each of these nonces from the secondary ECUs, then send them to the time server to fetch the current time. The time server responds as described in {{time_server}}, providing a cryptographic attestation of the last known time. The primary SHALL verify that the signatures are valid, and that the time the server attests is greater than the previous attested time.

#### Download and verify metadata {#download_meta_primary}

The primary SHALL download metadata for all targets and perform a full verification on it as specified in {{full_verification}}.

#### Download and verify images {#download_images_primary}

The primary SHALL download and verify images for itself and for all of its associated secondaries. Images SHALL be verified by checking that the hash of the image file matches the hash specified in the director's targets metadata for that image.

There may be several different filenames that all refer to the same image binary, as described in {{targets_meta}}. The primary SHALL associate each image binary with each of its possible filenames.

#### Send latest time to secondaries {#send_time_primary}

The primary SHALL send the time server's latest attested time to each ECU. The secondary SHALL verify the time message, then overwrite its current time with the received time.

#### Send metadata to secondaries {#send_metadata_primary}

The primary SHALL send the latest metadata it has downloaded to all of its associated secondaries.

Full verification secondaries SHALL keep a complete copy of all metadata. A partial verification secondary SHALL keep *only* the targets metadata file from the director repository.

#### Send images to secondaries {#send_images_primary}

The primary SHALL send the latest image to each of its associated secondaries that have storage to receive it.

For secondaries without storage, the primary SHOULD wait for a request from the secondary to stream the new image file to it. The secondary will send the request once it has verified the metadata sent in the previous step.

### Installing images on ECUs

Before installing a new image, an ECU SHALL perform the following five steps:

1. Verify latest attested time ({{verify_time}})
1. Verify metadata ({{verify_metadata}})
1. Download latest image ({{download_image}})
1. Verify image ({{verify_image}})
1. Create and send version report ({{create_version_report}})


#### Verify latest attested time {#verify_time}

The ECU SHALL verify the latest downloaded time. To do so, it must:

1. Verify that the signatures on the downloaded time are valid,
2. Verify that the list of nonces/tokens in the downloaded time includes the token that the ECU sent in its previous version report
3. Verify that the time downloaded is greater than the previous time

If all three steps complete without error, the ECU SHALL overwrite its current attested time with the time it has just downloaded and generate a new nonce/token for the next request to the time server.

If any check fails, the ECU SHALL NOT overwrite its current attested time, and SHALL jump to the fifth step ({{create_version_report}}). The ECU SHOULD reuse its previous token for the next request to the time server.

#### Verify metadata {#verify_metadata}

The ECU SHALL verify the latest downloaded metadata ({{metadata_verification}}) using either full or partial verification. If the metadata verification fails for any reason, the ECU SHALL jump to the fifth step ({{create_version_report}}).

#### Download latest image {#download_image}

If the ECU does not have secondary storage, it SHALL download the latest image from the primary. (If the ECU has secondary storage, it will already have the latest image in its secondary storage as specified in {{send_images_primary}}, and should skip to the next step.) The ECU MAY first create a backup of its previous working image and store it elsewhere (e.g., the primary).

The filename used to identify the latest known image (i.e., the file to request from the primary) SHALL be determined as follows: 

1. Load the targets metadata file from the director repository.
2. Find the targets metadata associated with this ECU identifier.
3. Construct the image filename using the rule in {{metadata_filename_rules}}.

When the primary responds to the download request, the ECU SHALL overwrite its current image with the downloaded image from the primary.

If any part of this step fails, the ECU SHALL jump to the fifth step ({{create_version_report}}).

#### Verify image {#verify_image}

The ECU SHALL verify that the latest image matches the latest metadata as follows:

1. Load the latest targets metadata file from the director.
2. Find the target metadata associated with this ECU identifier.
3. Check that the hardware identifier in the metadata matches the ECUs hardware identifier.
4. Check that the release counter of the image in the previous metadata, if it exists, is less than or equal to the release counter in the latest metadata.
5. If the image is encrypted, decrypt the image with a decryption key to be chosen as follows:
    * If the ECU key is a symmetric key, the ECU SHALL use the ECU key for image decryption.
    * If the ECU key is asymmetric, the ECU SHALL check the target metadata for an encrypted symmetric key. If such a key is found, the ECU SHALL decrypt the symmetric key using its ECU key, and use the decrypted symmetric key for image decryption.
    * If the ECU key is asymmetric and there is no symmetric key in the target metadata, the ECU SHALL use its ECU key for image decryption.
6. Check that the hash of the image matches the hash in the metadata.

If the ECU has secondary storage, the checks SHOULD be performed on the image in secondary storage, before it is installed.

If any step fails, the ECU SHALL jump to the fifth step ({{create_version_report}}). If the ECU does not have secondary storage, a step fails, and the ECU created a backup of its previous working image, the ECU SHOULD now install the backup image.

#### Create and send version report {#create_version_report}

The ECU SHALL create a version report as described in {{version_report}}, and send it to the primary (or simply save it to disk, if the ECU is a primary). The primary SHOULD write the version reports it receives to disk and associate them with the secondaries that sent them.

### Metadata verification {#metadata_verification}

A primary ECU MUST perform full verification of metadata. A secondary ECU SHOULD perform full verification of metadata, but MAY perform partial verification instead.

#### Partial verification {#partial_verification}

In order to perform partial verification, an ECU SHALL perform the following steps:

1. Load the latest attested time from the time server.
2. Load the latest top-level targets metadata file from the director repository.
3. Check that the metadata file has been signed by a threshold of keys specified in the previous root metadata file. If not, return an error code indicating an arbitrary software attack.
4. Check that the version number in the previous targets metadata file, if any, is less than or equal to the version number in this targets metadata file. If not, return an error code indicating a rollback attack.
5. Check that the latest attested time is lower than the expiration timestamp in this metadata file. If not, return an error code indicating a freeze attack.
6. Check that there are no delegations. If there are, return an error code.
7. Check that each ECU identifier appears only once. If not, return an error code.
8. Return an indicator of success.

#### Full verification {#full_verification}

Full verification of metadata means that the ECU checks that the targets metadata about images from the director repository matches the targets metadata about the same images from the image repository. This provides resilience to a key compromise in the system.

Full verification MAY be performed either by primary or secondary ECUs. The procedure is the same, except that secondary ECUs receive their metadata from the primary instead of downloading it directly. In the following instructions, whenever an ECU is directed to download metadata, it applies only to primary ECUs.

A primary ECU SHALL download metadata and images following the rules specified in {{TAP-5}}, and the metadata file renaming rules specified in {{metadata_filename_rules}}.

In order to perform full verification, an ECU SHALL perform the following steps:

1. If the ECU is a primary ECU, load the map file, and use the information therein to determine where to download metadata from.
2. Load the latest attested time from the time server.
3. Download and check the root metadata file from the director repository:
    1. Check that the metadata file has been signed by a threshold of keys specified in the previous root metadata file. (Checks for an arbitrary software attack.)
    2. Check that the version number in the previous targets metadata file, if any, is less than or equal to the version number in this targets metadata file. (Checks for a rollback attack.)
    3. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
    4. If the the timestamp and / or snapshot keys have been rotated, delete the previous timestamp and snapshot metadata files.
4. Download and check the timestamp metadata file from the director repository:
    1. Check that it has been signed by the threshold of keys specified in the root metadata file.
    2. Check that the version number of the previous timestamp metadata file, if any, is less than or equal to the version number of this timestamp metadata file. (Checks for a rollback attack.)
    3. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
5. Download and check the snapshot metadata file from the director repository:
    1. Check that it has been signed by the threshold of keys specified in the root metadata file.
    2. Check that the version number of the previous snapshot metadata file, if any, is less than or equal to the version number of this snapshot metadata file. (Checks for a rollback attack.)
    3. Check that the version number the previous snapshot metadata file lists for each targets metadata file is less than or equal to the its version number in this snapshot metadata file.
    4. Check that each targets metadata filename listed in the previous snapshot metadata file is also listed in this snapshot metadata file.
    5. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
6. Download and check the targets metadata file from the director repository:
    1. Check that it has been signed by the threshold of keys specified in the root metadata file.
    2. Check that the version number of the previous targets metadata file, if any, is less than or equal to the version number of this targets metadata file. (Checks for a rollback attack.)
    3. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
    4. Check that the version number in this targets metadata file matches the version number given for it in the snapshot metadata file. (Checks for a mix-and-match attack.)
    5. Check that there are no delegations. (Targets metadata from the director MUST NOT contain delegations.)
    6. Check that no ECU identifier is represented more than once.
7. Download and check the root metadata file from the image repository:
    1. Check that the metadata file has been signed by a threshold of keys specified in the previous root metadata file. (Checks for an arbitrary software attack.)
    2. Check that the version number in the previous targets metadata file, if any, is less than or equal to the version number in this targets metadata file. (Checks for a rollback attack.)
    3. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
    4. If the the timestamp and / or snapshot keys have been rotated, delete the previous timestamp and snapshot metadata files.
8. Download and check the timestamp metadata file from the image repository:
    1. Check that it has been signed by the threshold of keys specified in the root metadata file.
    2. Check that the version number of the previous timestamp metadata file, if any, is less than or equal to the version number of this timestamp metadata file. (Checks for a rollback attack.)
    3. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
9. Download and check the snapshot metadata file from the image repository:
    1. Check that it has been signed by the threshold of keys specified in the root metadata file.
    2. Check that the version number of the previous snapshot metadata file, if any, is less than or equal to the version number of this snapshot metadata file. (Checks for a rollback attack.)
    3. Check that the version number the previous snapshot metadata file lists for each targets metadata file is less than or equal to the its version number in this snapshot metadata file.
    4. Check that each targets metadata filename listed in the previous snapshot metadata file is also listed in this snapshot metadata file.
    5. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
10. Download and check the top-level targets metadata file from the image repository:
    1. Check that it has been signed by the threshold of keys specified in the root metadata file.
    2. Check that the version number of the previous targets metadata file, if any, is less than or equal to the version number of this targets metadata file. (Checks for a rollback attack.) {#test}
    3. Check that the latest attested time is lower than the expiration timestamp in this metadata file. (Checks for a freeze attack.)
    4. Check that the version number in this targets metadata file matches the version number given for it in the snapshot metadata file. (Checks for a mix-and-match attack.)
11. For each image listed in the targets metadata file from the director repository, locate a targets metadata file that contains an image with exactly the same file name. For each delegated targets metadata file that is found to contain metadata for the image currently being processed, perform all of the checks in step 10. Use the following process to locate image metadata:
    1. If the top-level targets metadata file contains signed metadata about the image, return the metadata to be checked and skip to step 11.3.
    2. Recursively search the list of delegations, in order of appearance:
        1. If it is a multi-role delegation, recursively visit each role, and check that each has signed exactly the same non-custom metadata (i.e., length and hashes) about the image. If it is all the same, return the metadata to be checked and skip to step 11.3.
        2. If it is a terminating delegation and it contains signed metadata about the image, return the metadata to be checked and skip to step 11.3. If metadata about an image is not found in a terminating delegation, return an error code indicating that the image is missing.
        3. Otherwise, continue processing the next delegation, if any. As soon as a delegation is found that contains signed metadata about the image, return the metadata to be checked and skip to step 11.3. 
        4. If no signed metadata about the image can be found anywhere in the delegation tree, return an error code indicating that the image is missing.
    3. Check that the targets metadata from the image repository matches the targets metadata from the director repository:
        1. Check that the length and hash of the image are the same in both sets of metadata.
        2. Check that the hardware identifier and release counter are the same in both sets of metadata.
        3. Check that the release counter in the previous targets metadata file is less than or equal to the release counter in this targets metadata file.

If any step fails, the ECU MUST return an error code indicating the failure. If a check for a specific type of security attack fails (e.g. rollback, freeze, arbitrary software, etc.), the ECU SHOULD return an error code that indicates the type of attack.

If the ECU performing the verification is the primary ECU, it SHOULD also ensure that the ECU identifiers present in the targets metadata from the director repository are a subset of the actual ECU identifiers of ECUs in the vehicle.

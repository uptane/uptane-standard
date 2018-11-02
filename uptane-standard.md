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
  USATODAY:
    target: https://www.usatoday.com/story/tech/columnist/2016/06/28/your-average-car-lot-more-code-driven-than-you-think/86437052/
    title: Your average car is a lot more code-driven than you think
    author:
      - ins: B. O'Donnell
    date: 2016-06-28
  CR-OTA:
    target: https://www.consumerreports.org/automotive-technology/automakers-embrace-over-the-air-updates-can-we-trust-digital-car-repair/
    title: Automakers Embrace Over-the-Air Updates, but Can We Trust Digital Car Repair?
    author:
      - ins: K. Barry
    date: 2018-04-20


--- abstract

This document describes a framework for securing automotive software update systems.

--- middle


# Introduction

Uptane is a secure software update framework for automobiles. This document describes procedures to enable programmers for OEMs and suppliers to design and implement this framework to better protect connected units on cars. Integrating Uptane as outlined in the sections that follow can reduce the ability of attackers to compromise critical systems. It also assures a faster and easier recovery process should a compromise occur.

These instructions specify the components necessary for a compliant implementation. Individual implementors can make their own technological choices within those requirements. This flexibility makes Uptane adaptable to the many customized update solutions used by manufacturers.

# Terminology

## Conformance Terminology

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be  interpreted as described in {{RFC2119}}.

In order to be considered “Uptane-compliant,” an implementation MUST follow all of these rules as specified in the document.

## Automotive Terminology

*Bus*: An internal communications network that interconnects components within a vehicle. A car can have a number of buses that will vary in terms of power, speed and resources.  
*Image*: File containing software for an ECU to install. May contain a binary image to flash, installation instructions, and other necessary information for the ECU to properly apply the update. Each ECU typically holds only one image, although this may vary in some cases.  
*Primary/Secondary ECUs*: Terms used to describe the control units within an automobile. A primary ECU downloads from a repository and verifies update images and metadata for itself and for secondary ECUs, and distributes images and metadata to secondaries. Thus, it requires extra storage space and a connection to the internet. Secondary ECUs receive their update images and metadata from the primary, and only need to verify and install their own metadata and images.  
*Repository*: A server containing metadata about images. May also contain the images themselves.  
*Suppliers*: Independent companies to which auto manufacturers may outsource the production of ECUs. Tier-1 suppliers directly serve the manufacturers. Tier-2 suppliers are those that receive outsourced work from Tier-1 suppliers.  
*Vehicle Version Manifest*: A compilation of all ECU version manifests on a vehicle. It serves as a master list of all images currently running on all ECUs in the vehicle.  

## Uptane Role Terminology

These terms are defined in greater detail in {{roles}}.

*Delegations*: Designating the responsibility of signing metadata about images to another party.  
*Roles*: The roles mechanism of Uptane allows the system to distribute signing responsibilities so that the compromise of one key does not necessarily impact the security of the entire system.

* *Root Role*: Distributes and revokes public keys used to verify the root, timestamp, snapshot, and targets role metadata.
* *Snapshot Role*: Indicates which images the repository has released at the same time.
* *Targets Role*: Holds the metadata used to verify the image, such as cryptographic hashes and file size.
* *Timestamp Role*: Indicates if there are any new metadata or image on the repository.


## Acronyms and Abbreviations

*CAN Bus*: Controller Area Network bus standard.  
*ECUs*: Electronic Control Units, the computing units on vehicle.  
*LIN Bus*: Local Interconnect Bus.  
*SOTA*: Software Updates Over-the-Air.  
*VIN*: Vehicle Identification Number.  

# Rationale for and Scope of Uptane Standards

This Standards document clarifies the essential components and best practices for the secure design implementation and deployment of Uptane by OEMs and suppliers. These practices contribute to compromise resilience, or the ability to minimize the extent of the threat posed by any given attack.

## Why Uptane requires standards

A standards document that can guide the safe design, integration and deployment of Uptane in cars is needed at this time because:

* The number of connected units on the average vehicle continues to grow, with mainstream cars now containing up to 100 million lines of code. {{USATODAY}}
* The expanded use of software over-the-air strategies creates new attack surfaces for malicious parties. {{CR-OTA}}
* Legacy update strategies, such as SSL/TLS or GPG/RSA, are not feasible for use on automotive ECUs because they force manufacturers to chose between enhanced security and customizability.
* Conventional strategies are also complicated by the differing resources of the ECUs, which can vary greatly in memory, storage space, and Internet connectivity.
* The design of Uptane makes it possible to offer improved design flexibility, without sacrificing security.
* This added design flexibility, however, could be a liability if the framework is implemented incorrectly.
* Standardization of crucial steps in the design, implementation and use of Uptane can assure that customizability does not impact security or functionality.

## Scope of Standards Coverage

This document sets guidelines for implementing Uptane in most systems capable of updating software on connected units in cars. In this section, we set the scope of that applicability by providing sample use cases and possible exceptions, aspects of update security that are not applicable to Uptane, and the design requirements governing the preparation of these standards.

### Use Cases

The following use cases provide a number of scenarios illustrating the manner in which software updates could be accomplished using Uptane.

#### OEMs initializing Uptane at the factory using SOTA

Bob, who works for an OEM, is overseeing the installation of Uptane on new vehicles at a manufacturing plant. He starts by preparing the ECUs by adding the following things: code to perform full/partial verification, the latest copy of the relevant metadata, the public keys, and the latest time, signed by the time server. His implementation would be considered Uptane-compliant if: a) all primaries perform full verification; b) all secondaries that are updated via OTA perform full / partial verification; and c) all other ECUs that perform no verification cannot be updated via OTA.

#### Updating one ECU with a complete image

Alice, a Tier-1 supplier, completes work on a revised image for an electronic brake control module. This module will control the brakes on all models of an SUV produced by the OEM for whom Clark is in charge of electronic systems. Alice signs the image, then delivers it and all of its metadata, including delegations, and associated images to Clark. Clark adds these metadata and images to the image repository, along with information about any dependencies and conflicts between this image and those on other ECUs. Clark also updates the inventory database, so that the director repository can instruct the ECU on how to install these updated images.

#### Dealership updating individual ECUs on demand

Dana runs a dealership for a major OEM. The OEM has issued a recall to address a problem with a keyless entry device that has been locking people out of their cars. Individual owners are bringing in a revised image on a flash drive that was sent to them from the manufacturer via courier mail. To carry out this update, the OEM would first have to delegate to Dana the authority to sign the metadata that would need to accompany the image on the flashdrive. He would then follow the same procedures used by Clark in the example above.

#### Update one ECU with multiple deltas

Frances needs to update an On-Board Diagnostics port and has several new images to download. To save bandwidth costs, she uses delta images that contain only the code and / or data that has changed from the previous image installed by the ECU. To do so, she must first modify the director repository, using the vehicle version manifest and dependency resolution to determine the differences between the previous and latest images. Frances then adds the following to the custom targets metadata used by the director repository (1) the algorithm used to apply a delta image, and (2) the targets metadata about the delta image. Frances would also check whether the delta images match the targets metadata from the director repository.

## Exceptions

There are a number of factors that could impede the completion of the above scenarios:
* ECUs may be lacking the necessary resources to function as designated. These resources could include weaknesses, in terms of CPU or RAM, that prevent performance of public key cryptography; or it may lack sufficient storage to undo installation of bad software; or it simply may reside on a low-speed network (e.g., LIN)
* ECUs may reside on different network segments, and may not be able to directly reach each other, requiring a gateway to facilitate communication.
* A user may replace OEM-installed ECUs with aftermarket ECUs instead.
* A vehicle may be able to download only a limited amount of data via a cellular channel (due to limits on a data plan).
* A system may lack sufficient power to download or install software updates.
* Vehicles may be offline for extended periods of time, thus missing required updates (e.g., key rotations).
* OEMs may be unwilling to implement costly security or hardware requirements.

## Out of Scope

The following topics will not be addressed in this document, as they represent threats outside the scope of Uptane:

* Physical attacks, such as manual tampering with ECUs outside the vehicle.
* Compromise of the supply chain (e.g., build system, version control system, packaging process). A number of strategies already (e.g., git signing, TPMs, in-toto) exist to address this problem. Therefore, there is no need duplicate those techniques here.
* Problems associated with OBD or UDS programming of ECUs, such as authentication of communications between ECUs.

## Design Requirements

The design requirements for this document are governed by three principal parameters:

* to clearly mandate the design and implementation steps that are security critical and must be followed as is, while offering flexibility in the implementation of non-critical steps. In this manner, users can adapt to support different use models and deployment scenarios.
* to delineate best practices to ensure that, should a vehicle be attacked, an attacker is forced to compromise many different systems.
* to ensure that, if implemented, the security practices mandated or suggested in this document do not interfere with the functionality of ECUs, vehicles, or the manufacturing systems on which they run.

# Threat Model and Attack Strategies

The overarching goal of Uptane is to provide a system that is resilient in the face of various types of compromise. In this section, we describe the goals that an attacker may have ({{attacker_goals}}) and the capabilities they may have or develop ({{capabilities}}). We then describe and classify types of attack on the system according to the attacker's goals ({{threats}}).

## Attacker goals {#attacker_goals}

We assume that attackers may want to achieve one or more of the following goals, in increasing order of severity:

* Read the contents of updates to discover confidential information or reverse-engineer firmware
* Deny installation of updates to prevent vehicles from fixing software problems
* Cause one or more ECUs in the vehicle to fail, denying use of the vehicle or of certain functions
* Control the vehicle or ECUs within the vehicle

## Attacker capabilities {#capabilities}

Uptane is designed with resilience to compromise in mind. We assume that attackers may develop one or more of the following capabilities:

* Read and analyze the contents of previous and/or current versions of software, as well as the update sequence and instructions
* Intercept and modify network traffic (i.e., perform man-in-the-middle attacks). This capability may be developed in two domains:
    * Outside the vehicle, intercepting and modifying traffic between the vehicle and software repositories
    * Inside the vehicle, intercepting and modifying traffic on one or more vehicle buses (e.g. via an OBD port or using a compromised ECU as a vector)
* Compromise and control one or more ECUs within a vehicle
* Compromise signing or encryption keys
* Compromise and control software repository servers (and any keys stored on the repository)

## Description of threats {#threats}

Uptane's threat model considers the following types of attack, organized according to the attacker goals listed in {{attacker_goals}}.

### Read updates {#read_updates}

* *Eavesdrop attack:* Read the unencrypted contents of an update sent from a repository to a vehicle.

### Deny installation of updates {#deny_updates}

An attacker seeking to deny installation of updates may attempt one or more of the following strategies:

* *Drop-request attack:* Block network traffic outside or inside the vehicle.
* *Slow retrieval attack:* Slow down network traffic, in the extreme case sending barely enough packets to avoid a timeout. Similar to a drop-request attack, except that both the sender and receiver of the traffic still think network traffic is unimpeded.
* *Freeze attack:* Continue to send a previously known update to an ECU, even if a newer update exists.
* *Partial bundle installation attack:* Install updates to some ECUs, but freeze updates on others.

### Interfere with ECU functionality {#change_functionality}

Attackers seeking to interfere with the functionality of vehicle ECUs in order to cause an operational failure or unexpected behaviour may do so in one of the following ways:

* *Rollback attack:* Cause an ECU to install a previously-valid software revision that is older than the currently-installed version.
* *Endless data attack:* Send a large amount of data to an ECU, until it runs out of storage, possibly causing the ECU to fail to operate.
* *Mix-and-match attack:* Install a set of images on ECUs in the vehicle that are incompatible with each other. This may be accomplished even if all of the individual images being installed are valid, as long as there exist valid versions that are mutually incompatible.
 
### Control an ECU or vehicle {#control_ecu}

Full control of a vehicle, or one or more ECUs within a vehicle, is the most severe threat.

* *Arbitrary software attack:* Cause an ECU to install and run arbitrary code of the attacker's choice.

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



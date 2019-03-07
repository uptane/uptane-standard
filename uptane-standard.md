---
title: Uptane IEEE-ISTO Standard for Design and Implementation
abbrev: UPTANE
docname: uptane-standard-design
category: info

ipr: noDerivativesTrust200902
area: TODO
workgroup: TODO
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - ins: Members of the Uptane Alliance Community
    name: Uptane Alliance Community
    organization: Uptane Alliance (c/o Prof. Justin Cappos)
    email: uptane-standards@googlegroups.com
    street: 6 MetroTech
    country: USA
    region: NY
    city: Brooklyn
    code: 11201

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
  # TAP 3 at rev d0818e5
  TAP-3:
    target: https://github.com/theupdateframework/taps/blob/d0818e580c322815a473520f2e8cc5f5eb8df499/tap3.md
    title: The Update Framework TAP 3 - Multi-role delegations
    author:
      - ins: T.K. Kuppusamy
      - ins: S. Awwad
      - ins: E. Cordell
      - ins: V. Diaz
      - ins: J. Moshenko
      - ins: J. Cappos
    date: 2018-01-18
  # TAP 4 at rev 2cb67d9
  TAP-4:
    target: https://github.com/theupdateframework/taps/blob/2cb67d913ec19424d1e354b38f862886fbfd4105/tap4.md
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
  # TUF at rev 2b4e184
  TUF-spec:
    target: https://github.com/theupdateframework/specification/blob/2b4e18472fe25d5b57f36f6fa50104967c8faeaa/tuf-spec.md
    title: The Update Framework Specification
    author:
      - ins: J. Samuel
      - ins: N. Mathewson
      - ins: G. Condra
      - ins: V. Diaz
      - ins: T.K. Kuppusamy
      - ins: S. Awwad
      - ins: S. Tobias
      - ins: J. Wright
      - ins: H. Mehnert
      - ins: E. Tryzelaar
      - ins: J. Cappos
      - ins: R. Dingledine
    date: 2018-09-19

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
    target: https://www.usenix.org/system/files/conference/atc17/atc17-kuppusamy.pdf
    title: "Mercury: Bandwidth-Effective Prevention of Rollback Attacks Against Community Repositories"
    author:
      - ins: T.K. Kuppusamy
      - ins: V. Diaz
      - ins: J. Cappos
    seriesinfo:
      ISBN: 978-1-931971-38-6
    date: 2017-07-12
  UPTANEESCAR:
    target: https://ssl.engineering.nyu.edu/papers/kuppusamy_escar_16.pdf
    title: "Securing Software Updates for Automobiles"
    author:
      - ins: T.K. Kuppusamy
      - ins: A. Brown 
      - ins: S. Awwad
      - ins: D. McCoy
      - ins: R. Bielawski
      - ins: C. Mott
      - ins: S. Lauzon
      - ins: A. Weimerskirch
      - ins: J. Cappos
    date: 2016-10-16
  PEP-458:
    target: https://www.python.org/dev/peps/pep-0458/
    title: "PEP 458 -- Surviving a Compromise of PyPI"
    author:
      - ins: T.K. Kuppusamy
      - ins: V. Diaz
      - ins: D. Stufft
      - ins: J. Cappos
    date: 2013-09-27
  DEPLOY:
    target: https://uptane.github.io/TODO
    title: "Uptane Deployment Guidelines"
  # TODO add TUF-CCS-2010
  # TODO add DIPLOMAT-NSDI-2016
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
  IN-TOTO:
    target: https://in-toto.github.io/
    title: "in-toto: A framework to secure the integrity of software supply chains"
    date: 2018-10-29


--- abstract

This document describes a framework for securing ground vehicle software update systems.

--- middle


# Introduction

Uptane is a secure software update framework for ground vehicles. This document describes procedures to enable programmers for OEMs and suppliers to securely design and implement this framework in a manner that better protects connected units on ground vehicles. Integrating Uptane as outlined in the sections that follow can reduce the ability of attackers to compromise critical systems. It also assures a faster and easier recovery process should a compromise occur.

These instructions specify the components necessary for a compliant implementation. Individual implementors can make their own technological choices within those requirements. This flexibility makes Uptane adaptable to the many customized update solutions used by manufacturers.

# Terminology

## Conformance Terminology

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be  interpreted as described in {{RFC2119}}.

In order to be considered “Uptane-compliant,” an implementation MUST follow all of these rules as specified in the document.

## Terminology

*Bundle*: A set of images released by the repository that is meant to be installed by one or more target ECUs on a vehicle at the same time.

*Bus*: An internal communications network that interconnects components within a vehicle. A vehicle can have a number of buses that will vary in terms of power, speed and resources.

*Image*: File containing software for an ECU to install. May contain a binary image to flash, installation instructions, and other necessary information for the ECU to properly apply the update. Each ECU typically holds only one image, although this may vary in some cases.  

*Primary/Secondary ECUs*: Terms used to describe the control units within a ground vehicle. A primary ECU downloads from a repository and verifies update images and metadata for itself and for secondary ECUs, and distributes images and metadata to secondaries. Thus, it requires extra storage space and a connection to the internet. Secondary ECUs receive their update images and metadata from the primary, and only need to verify and install their own metadata and images.  

*Repository*: A server containing metadata about images. May also contain the images themselves. Other data may be stored on the repository to be accessed by ECUs during the update process.

*Suppliers*: Independent companies to which auto manufacturers may outsource the production of ECUs. Tier-1 suppliers directly serve the manufacturers. Tier-2 suppliers are those that perform outsourced work for Tier-1 suppliers.  

*Vehicle Version Manifest*: A compilation of all ECU version manifests on a vehicle. It serves as a master list of all images currently running on all ECUs in the vehicle.  

## Uptane Role Terminology

These terms are defined in greater detail in {{roles}}.

*Delegations*: A process by which the responsibility of signing metadata about images is assigned to another party.  
*Role*: A party (human or machine) responsible for signing a certain type of metadata. The role controls keys and is responsible for signing metadata entrusted to it with these keys. The roles mechanism of Uptane allows the system to distribute signing responsibilities so that the compromise of one key does not necessarily impact the security of the entire system.

* *Root Role*: Signs metadata that distributes and revokes public keys used to verify the root, timestamp, snapshot, and targets role metadata.
* *Snapshot Role*: Signs metadata that indicates which images the repository has released at the same time.
* *Targets Role*: Sings metadata used to verify the image, such as cryptographic hashes and file size.
* *Timestamp Role*: Signs metadata that indicates if there are any new metadata or images on the repository.


## Acronyms and Abbreviations

*CAN Bus*: Controller Area Network bus standard  

*ECUs*: Electronic Control Units, the computing units on a vehicle

*LIN Bus*: Local Interconnect Bus  

*SOTA*: Software Updates Over-the-Air  

*VIN*: Vehicle Identification Number

# Rationale for and Scope of Uptane Standards

This Standards document clarifies the essential components and best practices for the secure design, implementation and deployment of Uptane by OEMs and suppliers. These practices contribute to compromise resilience, or the ability to minimize the extent of the threat posed by any given attack.

However, this specification is intended as an implementation guide, not as a detailed technical argument about the security properties that Uptane provides.  Readers interested in such documentation should refer to published papers that cover this topic.  {{UPTANEESCAR}}

## Why Uptane requires standards

A standards document that can guide the safe design, integration and deployment of Uptane in vehicles is needed at this time because:

* The number of connected units on the average vehicle continues to grow, with mainstream cars now containing up to 100 million lines of code. {{USATODAY}}
* The expanded use of software over-the-air strategies creates new attack surfaces for malicious parties. {{CR-OTA}}
* Legacy update strategies, such as SSL/TLS or GPG/RSA, are not feasible for use on vehicle ECUs because they force manufacturers to chose between enhanced security and customizability.
* Conventional strategies are also complicated by the differing resources of the ECUs, which can vary greatly in memory, storage space, and Internet connectivity.
* The design of Uptane makes it possible to offer improved design flexibility, without sacrificing security.
* This added design flexibility, however, could be a liability if the framework is implemented incorrectly.
* Standardization of crucial steps in the design, implementation and use of Uptane can assure that customizability does not impact security or functionality.

## Scope of Standards Coverage

This document sets guidelines for implementing Uptane in most systems capable of updating software on connected units in ground vehicles, including passenger vehicles, light-duty trucks, heavy-duty trucks, and motorcycles. Uptane could potentially also be applied to other ground vehicles such as automated shuttles, recreational vehicles, and military ground vehicles, and Uptane could even be applied to domains such as IoT devices, medical devices, and UAVs. In this section, we define the scope of that applicability by providing sample use cases and possible exceptions, aspects of update security that are not applicable to Uptane, and the design requirements governing the preparation of these standards.

### Assumptions

We assume the following system preconditions for Uptane:

* Vehicles have the ability to establish connectivity to required backend services. For example, this could be done through cellular, Wi-Fi, or hard-wired mechanisms.
* ECUs are either directly connected to the communication channel, or they are indirectly connected via some sort of network gateway.
* ECUs are programmable and provide sufficient performance to be updated.
* ECUs must be able to perform a public key cryptography operation as well as some supporting operations.
* There are state-of-the-art secure servers in place, such as the director and image repository servers.

### Use Cases

The following use cases provide a number of scenarios illustrating the manner in which software updates could be accomplished using Uptane.

#### OEMs initializing Uptane at the factory using SOTA

An OEM plans to install Uptane on new vehicles. This entails the following components: code to perform full and partial verification, the latest copy of the relevant metadata, the public keys, and the latest time, signed by the time server (if implemented). The OEM then either requires its tier-1 suppliers to provide these materials to the suppliers' assembly lines, or can choose to add the materials later at the OEM's assembly lines. The OEM's implementation is Uptane-compliant if:

1. all primaries perform full verification;
1. all secondaries that are updated via OTA perform full or partial verification; and
1. all other ECUs that do not perform verification cannot be updated via OTA.

#### Updating one ECU with a complete image

A tier-1 supplier completes work on a revised image for an electronic brake control module. This module will control the brakes on all models of an SUV produced by the OEM mentioned above. Each tier-1 supplier digitally signs the image, then delivers the signature and all of its metadata, including delegations, and associated images to the OEM. The OEM adds these metadata and images to its image repository, along with information about any dependencies and conflicts between this image and those on other ECUs used in the OEM's vehicles. The OEM also updates the inventory database, so that the director repository can instruct the ECU on how to install these updated images.

####  Updating individual ECUs on demand

An OEM has issued a recall to address a problem with a keyless entry device that has been locking people out of their cars. The OEM prepares an updated flash image in the manner described above. The OEM then ships USB flash drives to vehicle owners and dealerships that allow those parties to update the firmware of their vehicles.

#### Update one ECU with multiple deltas

The OEM wants to use delta updates to save over-the-air bytes. The delta images contain only the code and/or data that has changed from the previous image version. To do so, the OEM must first modify the director repository, using the vehicle version manifest and dependency resolution to determine the differences between the previous and latest images. The OEM then adds the following to the custom targets metadata used by the director repository: (1) the algorithm used to apply a delta image, and (2) the targets metadata about the delta image. The OEM will also check whether the delta images match the targets metadata from the director repository.

## Exceptions

There are a number of factors that could impede the completion of the above scenarios:

* ECUs may be lacking the necessary resources to function as designated. These resources could include weaknesses, in terms of CPU or RAM, that prevent performance of public key cryptography; a lack of sufficient storage to undo installation of bad software; or an ECU simply may reside on a low-speed network (e.g., LIN).
* ECUs may reside on different network segments, and may not be able to directly reach each other, requiring a gateway to facilitate communication.
* A user may replace OEM-installed ECUs with aftermarket ECUs.
* A vehicle may be able to download only a limited amount of data via a cellular channel, due to limits on a data plan.
* A system may lack sufficient power to download or install software updates.
* Vehicles may be offline for extended periods of time, thus missing required updates (e.g., key rotations).
* OEMs may be unwilling to implement costly security or hardware requirements.

## Out of Scope

The following topics will not be addressed in this document, as they represent threats outside the scope of Uptane:

* Physical attacks, such as manual tampering with ECUs outside the vehicle.
* Compromise of the supply chain (e.g., build system, version control system, packaging process). A number of strategies (e.g., git signing, TPMs, in-toto {{IN-TOTO}})  already exist to address this problem. Therefore, there is no need to duplicate those techniques here.
* Problems associated with OBD or UDS programming of ECUs, such as authentication of communications between ECUs.

## Design Requirements

The design requirements for this document are governed by the following principal parameters:

* to clearly mandate the design and implementation steps that are security critical and must be followed as is, while offering flexibility in the implementation of non-critical steps. In this manner, users can adapt to support different use models and deployment scenarios.
* to ensure that, if Uptane is implemented, the security practices mandated or suggested in this document do not interfere with the functionality of ECUs, vehicles, or the systems that maintain them.
* to delineate best practices to ensure that, should any part of the SOTA mechanism of a vehicle be attacked, an attacker must compromise two or more modules to breach the SOTA mechanism.

# Threat Model and Attack Strategies

The overarching goal of Uptane is to provide a system that is resilient in the face of various types of compromise. In this section, we describe the goals that an attacker may have ({{attacker_goals}}) and the capabilities they may have or could develop ({{capabilities}}). We then describe and classify types of attacks on the system according to the attacker's goals ({{threats}}).

## Attacker goals {#attacker_goals}

We assume that attackers may want to achieve one or more of the following goals, in increasing order of severity:

* Read the contents of updates to discover confidential information, reverse-engineer firmware, or compare two firmware images to identify security fixes and hence determine the fixed security vulnerability
* Deny installation of updates to prevent vehicles from fixing software problems
* Cause one or more ECUs in the vehicle to fail, denying use of the vehicle or of certain functions
* Control ECUs within the vehicle, and possibly the vehicle itself

## Attacker capabilities {#capabilities}

Uptane is designed with resilience to compromise in mind. We assume that attackers may develop one or more of the following capabilities:

* Intercept and modify network traffic (i.e., perform man-in-the-middle attacks). This capability may be developed in two domains:
    * Outside the vehicle, intercepting and modifying traffic between the vehicle and software repositories
    * Inside the vehicle, intercepting and modifying traffic on one or more vehicle buses (e.g. via an OBD port or using a compromised ECU as a vector)
* Compromise and control either a director repository or image repository server, and any keys stored on the repository, but not both the director and image repositories.
* Compromise either a primary ECU or a secondary ECU, but not both in the same vehicle

## Description of threats {#threats}

Uptane's threat model includes the following types of attacks, organized according to the attacker goals listed in {{attacker_goals}}.

### Read updates {#read_updates}

* *Eavesdrop attack:* Read the unencrypted contents of an update sent from a repository to a vehicle.

### Deny installation of updates {#deny_updates}

An attacker seeking to deny installation of updates may attempt one or more of the following strategies, among others:

* *Drop-request attack:* Block network traffic outside or inside the vehicle.
* *Slow retrieval attack:* Slow down network traffic, in the extreme case sending barely enough packets to avoid a timeout. Similar to a drop-request attack, except that both the sender and receiver of the traffic still think network traffic is unimpeded.
* *Freeze attack:* Continue to send a properly signed, but old, update bundle to the ECUs, even if newer updates exist.
* *Partial bundle installation attack:* Install a valid (signed) update bundle, and then block selected updates within the bundle.
* Conduct a denial of service attack against the Uptane repositories or infrastructure.

### Interfere with ECU functionality {#change_functionality}

Attackers seeking to interfere with the functionality of vehicle ECUs in order to cause an operational failure or unexpected behavior may do so in one of the following ways:

* *Rollback attack:* Cause an ECU to install a previously-valid software revision that is older than the currently-installed version.
* *Endless data attack:* Send a large amount of data to an ECU, until it runs out of storage, possibly causing the ECU to fail to operate.
* *Mix-and-match attack:* Install a malicious software bundle in which some of the updates do not interoperate properly. This may be accomplished even if all of the individual images being installed are valid, as long as valid versions exist that are mutually incompatible.

### Control an ECU or vehicle {#control_ecu}

Full control of a vehicle, or one or more ECUs within a vehicle, is the most severe threat.

* *Arbitrary software attack:* Cause an ECU to install and run arbitrary code of the attacker's choice.

# Detailed Design of Uptane

Uptane is a secure software update framework for automobiles. We do not specify implementation details. Instead, we describe the components necessary for a compliant implementation, and leave it up to individual implementors to make their own technological choices within those requirements.

At a high level, Uptane requires:

* Two software repositories:
    * An image repository containing binary images to install, and signed metadata about those images
    * A director repository connected to an inventory database that can sign metadata on demand for images in the image repository
* Repository tools for generating Uptane-specific metadata about images
* A public key infrastructure supporting the required metadata production/signing roles on each repository:
    * Root - Certificate authority for the Uptane ecosystem. Distributes public keys for verifying all the other roles' metadata
    * Timestamp - Indicates whether there are new metadata or images
    * Snapshot - Indicates images released by the repository at a point in time, via signing metadata about targets metadata
    * Targets - Indicates metadata about images, such as hashes and file sizes
* A secure way for ECUs to know the time. {{time_server}} describes one way to securely attest time to ECUs.
* An in-vehicle client on a primary ECU capable of verifying the signatures on all update metadata, handling all server communication, and downloading updates on behalf of secondary ECUs
* A client or library on each secondary ECU capable of performing either full or partial verification of metadata

## Roles on repositories {#roles}

A repository contains images and metadata. Each role has a particular type of metadata associated with it, as described in {{meta_structures}}.

### The Root role {#root_role}

A repository's Root role SHALL be responsible for a Certificate Authority as defined in {{RFC3647}}.
A repository's Root role SHALL produce and sign Root metadata as described in {{root_meta}}.
A repository's Root role SHALL sign the public keys used to verify the metadata produced by the Timestamp, Snapshot, and Targets roles.
A repository's Root role SHALL revoke keys for the other roles, in case of compromise.

### The Targets role {#targets_role}

A repository's Targets role SHALL produce and sign metadata about images and delegations as described in {{targets_meta}}.

#### Delegations {#targets_role_delegations}

The Targets role on the Image repository MAY delegate the responsibility of signing metadata to other, custom-defined roles referred to as delegated targets. If it does, it MUST do so as specified in {{delegations_meta}}.

Responsibility for signing images or a subset of images MAY be delegated to more than one role and therefore it is possible for two different roles to be trusted for signing a particular image. For this reason, delegations MUST be prioritized.

A particular delegation for a subset of images MAY be designated as **terminating**. For terminating delegations, the client SHALL NOT search any further if it does not find validly signed metadata about those images in the terminating delegation. Delegations SHOULD NOT be terminating by default; terminating delegations SHOULD only be used when there is a compelling technical reason to do so.

A delegation for a subset of images MAY be a multi-role delegation {{TAP-3}}. A multi-role delegation indicates that multiple roles are needed to sign a particular image and so each of the delegatee roles MUST sign the same metadata.

Delegations only apply to the Image repository. The Targets role on the Director repository MUST NOT delegate metadata signing responsibility.

### The Snapshot role {#snapshot_role}

A repository's Snapshot role SHALL produce and sign metadata about all Targets metadata the repository releases, including the current version number and hash of the top-level Targets metadata, and the version numbers and hashes of all delegated targets metadata, as described in {{snapshot_meta}}.

### The Timestamp role {#timestamp_role}

A repository's Timestamp role SHALL produce and sign metadata indicating whether there are new metadata or images on the repository. It MUST do so by signing the metadata about the Snapshot metadata file.

## Metadata structures {#meta_structures}

Uptane's security guarantees all rely on properly created metadata that follow a designated structure. The Uptane standard **does not** mandate any particular format or encoding for this metadata. ASN.1 (with any encoding scheme like BER, DER, XER, etc.), JSON, XML, or any other encoding format that is capable of providing the required structure MAY be used.

In the Deployment Considerations document, the Uptane Alliance provides some examples of compliant metadata structures in ASN.1 and JSON.

### Common Metadata Structures {#common_metadata}

Every public key MUST be represented using a public key identifier.  A public key identifier is EITHER all of the following:

* The value of the public key itself (which MAY be, for example, formatted as a PEM string)
* The public key cryptographic algorithm used by the key (such as RSA or ECDSA)
* The particular scheme used to verify the signature (such as `rsassa-pss-sha256` or `ecdsa-sha2-nistp256`)

OR a secure hash over at least the above components (such as the keyid mechanism in TUF).

All four Uptane roles (Root, Targets, Snapshot, and Timestamp) share a common structure. They SHALL contain the following two attributes:

* A payload of metadata to be signed
* An attribute containing the signature(s) of the payload, where each entry specifies:
  * The public key identifier of the key being used to sign the payload
  * A signature with this key over the payload

The payload differs depending on the role. However, the payload for all roles shares a common structure. It SHALL contain the following four attributes:

* An indicator of the type of role (Root, Targets, Snapshot, or Timestamp)
* An expiration date and time
* An integer version number, which SHOULD be incremented each time the metadata file is updated
* The role-specific metadata for the role indicated

The following sections describe the role-specific metadata. All roles SHALL follow the common structures described here.

### Root Metadata {#root_meta}

A repository's Root metadata distributes the public keys of the top-level Root, Targets, Snapshot, and Timestamp roles, as well as revocations of those keys. It SHALL contain two attributes:

* A representation of the public keys for all four roles. Each key should have a unique public key identifier.
     * If a Time Server is in use, a representation of the Time Server public key is CONDITIONALLY REQUIRED in Director repository root metadata.
* An attribute mapping each role to (1) its public key(s), and (2) the threshold of signatures required for that role

Additionally, it MAY contain a mapping of roles to a list of valid URLs from which the role metadata can be downloaded.  If this mapping of URLs is used, the implementer SHOULD implement this functionality following {{TAP-5}} to avoid adding unforeseen security risks.

### Targets Metadata {#targets_meta}

Targets metadata, whether for the top-level Targets role or for any delegated targets role, MAY contain metadata about images on a repository. It MAY also contain metadata about delegations of signing authority.

#### Metadata about Images {#targets_images_meta}

To be available to install on clients, all images on the repository MUST have their metadata listed in a targets role.  Each targets role MAY provide a list of some images on the repository.  This list MUST provide, at a minimum, the following information about each image:

* The image filename
* The size of the image in bytes
* One or more hashes of the image file, along with the hashing function used

##### Custom metadata about images

In addition to the required metadata, the Targets metadata file SHOULD contain extra metadata for each image on the repository. This metadata can be customized for a particular use case. Examples of use cases for different types of custom metadata can be found in the Deployment Considerations document. However, there are a few important pieces of custom metadata that SHOULD be present in most implementations.

The following information SHOULD be provided for each image on both the Image repository and the Director repository:

* A release counter, to be incremented each time a new version of the image is released. This can be used to prevent rollback attacks even in cases where the director repository is compromised.
* A hardware identifier, or list of hardware identifiers, representing models of ECUs with which the image is compatible. This can be used to ensure that an ECU can not be ordered to install an incompatible image, even in cases where the Director repository is compromised.

The following information SHOULD be provided for each image on the director repository:

* An ECU identifier, specifying (by serial number, for example) the ECU that should install the image.
* If encrypted images are desired, information about filenames, hashes, and file size of the encrypted image
* If encrypted images are desired, information about the encryption method, and other relevant information--for example, a symmetric encryption key encrypted by the ECU's asymmetric key could be included in the Director repository metadata.

The Director repository MAY provide a download URL for the image file. This may be useful, for example, when the image is on a public CDN and the director wishes to provide a signed URL.

#### Metadata about Delegations {#delegations_meta}

A Targets metadata file on the Image repository (but not the Director repository) MAY delegate signing authority to other entities--for example, it could delegate signing authority for a particular ECU's firmware to that ECU's supplier. A metadata file MAY contain more than one delegation, and MUST keep the delegations in prioritized order.

A list of delegations MUST provide the following information:

* A list of public keys of all delegatees. Each key should have a unique public key identifier, and a key type.
* A list of delegations, each of which contains:
  * A list of the filenames to which this role applies. This MAY be expressed using wildcards, or by enumerating a list, or a combination of the two.
  * An optional list of the hardware identifiers to which this role applies.  If this is omitted, any hardware identifier will match.
  * An indicator of whether or not this is a terminating delegation. (See {{targets_role_delegations}}.)
  * A list of the roles to which this delegation applies. Each role needs to specify:
    * A name for the role (e.g. "supplier1-qa")
    * The key identifiers for each key this role uses
    * A threshold of keys that must sign for this role

Note that **any** targets metadata file may contain delegations, and that delegations can be in chains of arbitrary length.

#### Metadata about Time Server

If a Time Server {{time_server}} is implemented AND partial-verification secondaries will be used, the following metadata is CONDITIONALLY REQUIRED in the Director repository's Targets metadata:

* A representation of the public key(s) for the Time Server, similar to the representation of public keys in Root metadata.

Listing the public key of the Time Server in Director targets metadata is necessary to allow partial-verification secondaries to perform time server key rotation.

### Snapshot Metadata {#snapshot_meta}

The Snapshot metadata lists version numbers and filenames of all Targets metadata files. It protects against mix-and-match attacks if a delegated supplier key is compromised.

For each Targets metadata file on the repository, the Snapshot metadata SHALL contain the following information:

* The filename and version number of the each Targets metadata file on the repository

The Snapshot metadata MAY also list the root metadata filename and version number. This is not required, particularly for implementations of {{TAP-5}}, but MAY be included in all cases for backwards compatibility.

### Timestamp Metadata {#timestamp_meta}

The Timestamp metadata SHALL contain the following information:

* The filename and version number of the latest snapshot metadata on the repository.
* One or more hashes of the snapshot metadata file, along with the hashing function used.

### Repository mapping metadata {#repo_mapping_meta}

Repository mapping metadata informs a primary ECU about which repositories to trust for images or image paths. Repository mapping metadata MUST be present on all primary ECUs, and MUST contain the following information:

* A list of repository names and one or more URLs at which the named repository can be accessed. At a minimum, this MUST include the Director and Image repositories.
* A list of mappings of image paths to repositories, each of which contains:
    * A list of image paths. Image paths MAY be expressed using wildcards, or by enumerating a list, or a combination of the two.
    * A list of repositories that MUST sign the targets metadata for the image paths.

For example, in the most basic Uptane case, the repository mapping metadata would contain:

* The name and URL of the Director repository
* The name and URL of the Image repository
* A single mapping indicating that all images (`*`) MUST be signed by both the Director and Image repository

However, more complex repository mapping metadata can permit more complicated use cases. For example:

* A second Director repository might be useful for fleet management of after-market vehicles, such as a rental car company that might wish to only install approved updates.
* For dynamic content with lower security sensitivity, an OEM might want to allow a certain subset of images to only require trust from the Director repository.

The *Deployment Considerations* document gives more guidance on how to implement repository mapping metadata for these use cases. It also discusses strategies for updating repository mapping metadata, if required. {{TAP-4}} also contains detailed guidance on repository mapping metadata implementation.

Note that repository mapping metadata might not be a file, and MAY be expressed in a different format than the repository roles metadata. For example, it could be part of the primary ECU's Uptane client configuration. As long as the client has access to the required information, the repository mapping metadata requirements are met.

### Rules for filenames in repositories and metadata {#metadata_filename_rules}

There is a difference between the file name in a metadata file or an ECU, and the file name on a repository. This difference exists in order to avoid race conditions, where metadata and images are read from, and written to, at the same time. For more details, the reader should read the TUF specification {{TUF-spec}} and PEP 458 {{PEP-458}}.

Unless stated otherwise, all files SHALL be written to repositories in accordance with following two rules:

1. Metadata filenames SHALL be qualified with version numbers. If a metadata file A is specified as FILENAME.EXT in another metadata file B, then it SHALL be written as VERSION.FILENAME.EXT, where VERSION is A's version number, as defined in {{common_metadata}}, with one exception: If the version number of the Timestamp metadata file might not be known in advance by a client, it MAY be read from, and written to, a repository using a filename without a version number qualification, i.e. FILENAME.EXT.
2. If an image is specified in a targets metadata file as FILENAME.EXT, it SHALL be written to the repository as HASH.FILENAME.EXT, where HASH is one of the hash digests of the file, as specified in {{targets_images_meta}}. The file MUST be written to the repository using *n* different filenames, one for each hash digest listed in its corresponding targets metadata.

For example:

* The version number of the Snapshot metadata file is 61, and its filename in the Timestamp metadata is "snapshot.json". The filename on the repository will be "61.snapshot.json".
* There is an image with the filename "acme_firmware.bin" specified in the Targets metadata, with a SHA256 of "aaaa" and a SHA512-256 of "bbbb". It will have two filenames on the repository: "aaaa.acme_firmware.bin" and "bbbb.acme_firmware.bin".

## Server / repository implementation requirements

An Uptane implementation SHALL make the following services available to vehicles:

* Image repository
* Director repository

Additionally, an Uptane implementation requires ECUs to have a secure way to know the current time. This SHOULD be accomplished using a time server ({{time_server}}), but MAY be implemented in other ways.

### Image Repository

The Image repository exists to allow an OEM and/or its suppliers to upload images and their associated metadata. It makes these images and their metadata available to vehicles. The Image repository is designed to be primarily controlled by human actors, and updated relatively infrequently.

The Image repository SHALL expose an interface permitting the download of metadata and images. This interface SHOULD be public.

The Image repository SHALL require authorization for writing metadata and images.

The Image repository SHALL provide a method for authorized users to upload images and their associated metadata. It SHALL check that a user writing metadata and images is authorized to do so for that specific image by checking the chain of delegations as described in {{delegations_meta}}.

The Image repository SHALL implement storage which permits authorized users to write an image file using a unique filename, and later read the same file using the same name. It MAY use any filesystem, key-value store, or database that fulfills this requirement.

The Image repository MAY require authentication for read access.

### Director Repository {#director_repository}

The Director repository instructs ECUs as to which images should be installed by producing signed metadata on demand. Unlike the Image repository, it is mostly controlled by automated, online processes. It also consults a private inventory database containing information on vehicles, ECUs, and software revisions.

The Director repository SHALL expose an interface for primaries to upload vehicle version manifests ({{vehicle_version_manifest}}) and download metadata. This interface SHOULD be public.
The Director MAY encrypt images for ECUs that require them, either by encrypting on-the-fly or by storing encrypted images in the repository.

The Director repository SHALL implement storage which permits an automated service to write generated metadata files. It MAY use any filesystem, key-value store, or database that fulfills this requirement.

#### Directing installation of images on vehicles

A Director repository MUST conform to the following six-step process for directing the installation of software images on a vehicle.

1. When the Director receives a vehicle version manifest sent by a primary (as described in {{construct_manifest_primary}}), it decodes the manifest, and determines the unique vehicle identifier.
1. Using the vehicle identifier, the Director queries its inventory database (as described in {{inventory_db}}) for relevant information about each ECU in the vehicle.
1. The Director checks the manifest for accuracy compared to the information in the inventory database. If any of the required checks fail, the Director drops the request. An implementor MAY make whatever additional checks they wish. At a minimum, the Director SHALL check the following:
    * Each ECU recorded in the inventory database is also represented in the manifest.
    * The signature of the manifest matches the ECU key of the primary that sent it.
    * The signature of each secondary's contribution to the manifest matches the ECU key of that secondary.
1. The Director extracts information about currently installed images from the vehicle version manifest. Using this information, it determines if the vehicle is already up-to-date, and if not, determines a set of images that should be installed. The exact process by which this determination takes place is out of scope of this standard. However, the Director MUST take into account *dependencies* and *conflicts* between images, and SHOULD consult well-established techniques for dependency resolution.
1. The Director MAY encrypt images for ECUs that require it.
1. The Director generates new metadata representing the desired set of images to be installed on the vehicle, based on the dependency resolution in step 4. This includes targets ({{targets_meta}}), snapshot ({{snapshot_meta}}), and timestamp ({{timestamp_meta}}) metadata. It then sends this metadata to the primary as described in {{download_meta_primary}}.

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

The Time Server exists to inform vehicles about the current time in a cryptographically secure way, since many ECUs in a vehicle will not have a reliable source of time. It receives lists of tokens from vehicles, and returns back a signed sequence that includes the token and the current time.

An Uptane implementation SHOULD include a time server, but MAY use another secure source of time. If the time server is used, it MUST conform to the following requirements:

When the Time Server receives a sequence of tokens from a vehicle, it SHALL provide one or more signed responses, containing the time along with these tokens. It MAY produce either one signed time attestation containing the current time and all tokens, or multiple time attestations each containing the current time and one or more tokens.

The Time Server SHALL expose a public interface allowing primaries to communicate with it. This communication MAY occur over FTP, FTPS, SFTP, HTTP, or HTTPS.

Rotation of the The Time Server's key is performed by listing the new key in the Director's Root metadata, in the same manner as other role keys are listed, and also in the Director's Targets metadata (for partial verification secondaries).

## In-vehicle implementation requirements

An Uptane-compliant ECU SHALL be able to download and verify the time, metadata, and image binaries before installing a new image.

Each ECU in a vehicle receiving over-the-air updates is either a primary or a secondary ECU. A primary ECU collects and delivers to the Director vehicle manifests ({{vehicle_version_manifest}}) containing information about which images have been installed on ECUs in the vehicle. It also downloads and verifies the latest time, metadata, and images for itself and for its secondaries. A secondary ECU downloads and verifies the latest time, metadata, and images for itself from its associated primary ECU. It also sends signed information about its installed images to its associated primary.

All ECUs MUST verify image metadata as specified in {{metadata_verification}} before installing an image or making it available to other ECUs. A primary ECU MUST perform full verification ({{full_verification}}). A secondary ECU SHOULD perform full verification if possible. See [Uptane Deployment Considerations](#DEPLOY) for a discussion of how to choose between partial and full verification.

### Build-time prerequisite requirements for ECUs

For an ECU to be capable of receiving Uptane-secured updates, it MUST have the following data provisioned at the time it is manufactured or installed in the vehicle:

1. A sufficiently recent copy of required Uptane metadata at the time of manufacture or install. See [Uptane Deployment Considerations](#DEPLOY) for more information.
    * Partial verification ECUs MUST have the Root and Targets metadata from the Director repository.
    * Full verification ECUs MUST have a complete set of metadata (root, targets, snapshot, and timestamp) from both repositories, as well as the repository mapping metadata ({{repo_mapping_meta}}).
2. The public key(s) of the time server (if the time server is implemented).
3. The current time. This SHOULD be in the form of an attestation of time downloaded from the time server, but MAY come from another source if the time server is not implemented.
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

Once it has the complete manifest built, it MAY send the manifest to the Director repository. However, it is not strictly required that the primary send the manifest until step three.

Secondaries MAY send their version report at any time, so that it is already stored on the primary  when it wishes to check for updates. Alternatively, the primary MAY request a version report from each secondary at the time of the update check.

##### Vehicle version manifest {#vehicle_version_manifest}

The vehicle version manifest is a metadata structure that MUST contain the following information:

* An attribute containing the signature(s) of the payload, each specified by:
  * The public key identifier of the key being used to sign the payload
  * The signing method (e.g. ed25519, rsassa-pss, etc.)
  * A hash of the payload to be signed
  * The hashing function used (e.g. sha256, sha512-224, etc.)
  * The signature of the hash
* A payload representing the installed versions of each software image on the vehicle. This payload SHALL contain:
  * The vehicle's unique identifier (e.g. the VIN)
  * The primary ECU's unique identifier (e.g. the serial number)
  * A list of ECU version reports as specified in {{version_report}}

Note that one of the ECU version reports should be the version report for the primary itself.

##### ECU version report {#version_report}

An ECU version report is a metadata structure that MUST contain the following information:

* An attribute containing the signature(s) of the payload, each specified by:
  * The public key identifier of the key being used to sign the payload
  * The signing method (e.g. ed25519, rsassa-pss, etc.)
  * A hash of the payload to be signed
  * The hashing function used (e.g. sha256, sha512-224, etc.)
  * The signature of the hash
* A payload containing:
  * The ECU's unique identifier (e.g. the serial number)
  * The latest time downloaded from the time server, if the time server is implemented
  * The previous time downloaded from the time server, if the time server is implemented
  * The filename, length, and hashes of its currently installed image (i.e. the non-custom targets metadata for this particular image)
  * An indicator of any detected security attack
* A token (nonce) for the time server to sign and send back, if the time server is implemented

#### Download and check current time {#check_time_primary}

The primary SHALL load the current time from a secure source. This secure source SHOULD be a time server as described in {{time_server}}.

If the time server is implemented, the primary SHALL use the following procedure to verify the time:

1. Gather the tokens/nonces from each secondary ECU's version report ({{version_report}}).
2. Send the list of tokens to the time server to fetch the current time. The time server responds as described in {{time_server}}, providing a cryptographic attestation of the last known time.
3. Verify that the signatures are valid, and that the time the server attests is greater than the previous attested time.

#### Download and verify metadata {#download_meta_primary}

The primary SHALL download metadata for all targets and perform a full verification on it as specified in {{full_verification}}.

#### Download and verify images {#download_images_primary}

The primary SHALL download and verify images for itself and for all of its associated secondaries. Images SHALL be verified by checking that the hash of the image file matches the hash specified in the director's targets metadata for that image.

There may be several different filenames that all refer to the same image binary, as described in {{targets_meta}}. The primary SHALL associate each image binary with each of its possible filenames.

#### Send latest time to secondaries {#send_time_primary}

The primary SHOULD send the time to each ECU. The secondary will verify the time message, then overwrite its current time with the received time.

#### Send metadata to secondaries {#send_metadata_primary}

The primary SHALL send its latest downloaded metadata to all of its associated secondaries. The metadata it sends to each secondary MUST include all of the metadata required for verification on that secondary. For full verification secondaries, this includes the metadata for all four roles from both repositories, plus any delegated targets metadata files the secondary will recurse through to find the proper delegation. For partial verification secondaries, this includes only the targets metadata file from the director repository.

The primary SHOULD determine the minimal set of metadata files to send to each secondary, by performing delegation resolution as described in {{full_verification}}.

Each secondary SHALL store the latest copy of all metadata required for its own verification.

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


#### Load and verify the latest attested time {#verify_time}

The ECU SHOULD load and verify the current time, or the most recent time from the time server if it is implemented.

If an Uptane time server ({{time_server}}) is implemented, the ECU SHALL:

1. Verify that the signatures on the downloaded time are valid.
2. Verify that the list of nonces/tokens in the downloaded time includes the token that the ECU sent in its previous version report.
3. Verify that the time downloaded is greater than the previous time.

If all three steps complete without error, the ECU SHALL overwrite its current attested time with the time it has just downloaded, and generate a new nonce/token for the next request to the time server.

If any check fails, the ECU SHALL NOT overwrite its current attested time, and SHALL jump to the fifth step ({{create_version_report}}), and report the error. The ECU MUST reuse its previous token for the next request to the time server.

#### Verify metadata {#verify_metadata}

The ECU SHALL verify the latest downloaded metadata ({{metadata_verification}}) using either full or partial verification. If the metadata verification fails for any reason, the ECU SHALL jump to the fifth step ({{create_version_report}}).

#### Download latest image {#download_image}

If the ECU does not have secondary storage, i.e. buffer storage to temporarily store the latest image before installing it, it SHALL download the latest image from the primary. (If the ECU has secondary storage, it will already have the latest image in its secondary storage as specified in {{send_images_primary}}, and should skip to the next step.) The ECU MAY first create a backup of its previous working image and store it elsewhere (e.g., the primary).

The filename used to identify the latest known image (i.e., the file to request from the primary) SHALL be determined as follows:

1. Load the Targets metadata file from the Director repository.
2. Find the Targets metadata associated with this ECU identifier.
3. Construct the Image filename using the rule in {{metadata_filename_rules}}, or use the download URL specified in the Director metadata.
4. If there is no Targets metadata about this image, abort the update cycle and report that there is no such image. Otherwise, download the image (up to the number of bytes specified in the Targets metadata), and verify that its hashes match the Targets metadata.

When the primary responds to the download request, the ECU SHALL overwrite its current image with the downloaded image from the primary.

If any part of this step fails, the ECU SHALL jump to the fifth step ({{create_version_report}}).

#### Verify image {#verify_image}

The ECU SHALL verify that the latest image matches the latest metadata as follows:

1. Load the latest Targets metadata file from the director.
2. Find the Targets metadata associated with this ECU identifier.
3. Check that the hardware identifier in the metadata matches the ECUs hardware identifier.
4. Check that the image filename is valid for this ECU. This MAY be a comparison against a wildcard path, and restricts the ECUs a delegation applies to.
5. Check that the release counter of the image in the previous metadata, if it exists, is less than or equal to the release counter in the latest metadata.
6. If the image is encrypted, decrypt the image with a decryption key to be chosen as follows:
    * If the ECU key is a symmetric key, the ECU SHALL use the ECU key for image decryption.
    * If the ECU key is asymmetric, the ECU SHALL check the target metadata for an encrypted symmetric key. If such a key is found, the ECU SHALL decrypt the symmetric key using its ECU key, and use the decrypted symmetric key for image decryption.
    * If the ECU key is asymmetric and there is no symmetric key in the target metadata, the ECU SHALL use its ECU key for image decryption.
7. Check that the hash of the image matches the hash in the metadata.

If the ECU has secondary storage, the checks SHOULD be performed on the image in secondary storage, before it is installed.

If any step fails, the ECU SHALL jump to the fifth step ({{create_version_report}}). If a step fails and the ECU does not have secondary storage, and the ECU has created a backup of its previous working image, the ECU SHOULD now install the backup image.

#### Create and send version report {#create_version_report}

The ECU SHALL create a version report as described in {{version_report}}, and send it to the primary (or simply save it to disk, if the ECU is a primary). The primary SHOULD write the version reports it receives to disk and associate them with the secondaries that sent them.

### Metadata verification procedures {#metadata_verification}

A primary ECU MUST perform full verification of metadata. A secondary ECU SHOULD perform full verification of metadata, but MAY perform partial verification instead.

If a step in the following workflows does not succeed (e.g., the update is aborted because a new metadata file was not signed), an ECU SHOULD still be able to update again in the future. Errors raised during the update process SHOULD NOT leave ECUs in an unrecoverable state.

#### Partial verification {#partial_verification}

In order to perform partial verification, an ECU SHALL perform the following steps:

1. Load the latest attested time from the time server, if implemented.
2. Download and check the Targets metadata file from the Director repository, following the procedure in {{check_targets}}.

#### Full verification {#full_verification}

Full verification of metadata means that the ECU checks that the Targets metadata about images from the Director repository matches the Targets metadata about the same images from the Image repository. This provides resilience to a key compromise in the system.

Full verification MAY be performed by either primary or secondary ECUs. The procedure is the same, except that secondary ECUs receive their metadata from the primary instead of downloading it directly. In the following instructions, whenever an ECU is directed to download metadata, it applies only to primary ECUs.

If {{TAP-5}} is supported, a primary ECU SHALL download metadata and images following the rules specified in that TAP.  If {{TAP-5}} is not supported, the download should follow the {{TUF-spec}} and the metadata file renaming rules specified in {{metadata_filename_rules}}.

In order to perform full verification, an ECU SHALL perform the following steps:

1. Load the repository mapping metadata ({{repo_mapping_meta}}), and use the information therein to determine from where metadata should be downloaded.
2. Load the latest attested time from the time server, if implemented.
3. Download and check the Root metadata file from the Director repository, following the procedure in {{check_root}}.
4. Download and check the Timestamp metadata file from the Director repository, following the procedure in {{check_timestamp}}.
5. Download and check the Snapshot metadata file from the Director repository, following the procedure in {{check_snapshot}}.
6. Download and check the Targets metadata file from the Director repository, following the procedure in {{check_targets}}.
7. Download and check the Root metadata file from the Image repository, following the procedure in {{check_root}}.
8. Download and check the Timestamp metadata file from the Image repository, following the procedure in {{check_timestamp}}.
9. Download and check the Snapshot metadata file from the Image repository, following the procedure in {{check_snapshot}}.
10. Download and check the top-level Targets metadata file from the Image repository, following the procedure in {{check_targets}}.
11. For each image listed in the Targets metadata file from the Director repository downloaded in step 6, complete the following procedure:
    1. Locate and download a Targets metadata file that contains an image with exactly the same file name, following the procedure in {{resolve_delegations}}.
    2. Check that the Targets metadata from the Image repository matches the Targets metadata from the Director repository:
        1. Check that the non-custom metadata (i.e., length and hashes) of the unencrypted image are the same in both sets of metadata.
        2. Check that the custom metadata (e.g., hardware identifier and release counter) are the same in both sets of metadata.
        3. Check that the release counter in the previous targets metadata file is less than or equal to the release counter in this targets metadata file.

If any step fails, the ECU MUST return an error code indicating the failure. If a check for a specific type of security attack fails (e.g. rollback, freeze, arbitrary software, etc.), the ECU SHOULD return an error code that indicates the type of attack.

If the ECU performing the verification is the primary ECU, it SHOULD also ensure that the ECU identifiers present in the targets metadata from the director repository are a subset of the actual ECU identifiers of ECUs in the vehicle.

#### How to check Root metadata {#check_root}

1. Load the previous Root metadata file.
2. Update to the latest Root metadata file.
    1. Let N denote the version number of the latest Root metadata file (which at first could be the same as the previous root metadata file).
    2. Try downloading a new version N+1 of the Root metadata file, up to some X number of bytes. The value for X is set by the implementor. For example, X may be tens of kilobytes. The filename used to download the root metadata file is of the fixed form VERSION_NUMBER.FILENAME.EXT (e.g., 42.root.json). If this file is not available, the current Root metadata file is the latest; continue with step 3.
    3. Version N+1 of the Root metadata file MUST have been signed by: (1) a threshold of keys specified in the latest Root metadata file (version N), and (2) a threshold of keys specified in the new Root metadata file being validated (version N+1). If version N+1 is not signed as required, discard it, abort the update cycle, and report the signature failure. On the next update cycle, begin at version N of the root metadata file. (Checks for an arbitrary software attack.)
    4. The version number of the latest Root metadata file (version N) must be less than or equal to the version number of the new Root metadata file (version N+1). Effectively, this means checking that the version number signed in the new Root metadata file is indeed N+1. If the version of the new Root metadata file is less than the latest metadata file, discard it, abort the update cycle, and report the rollback attack. On the next update cycle, begin at step 0 and version N of the Root metadata file. (Checks for a rollback attack.)
    5. Set the latest Root metadata file to the new Root metadata file.
    6. Repeat steps 2.1 to 2.6.
3. If the Timeserver key is listed in the Root metadata and has been rotated, reset the clock used to determine the expiration of metadata to a minimal value (e.g. zero, or any time that is guaranteed to not be in the future based on other evidence).  It will be updated in the next cycle.
4. Check that the latest attested time is lower than the expiration timestamp in the latest Root metadata file. (Checks for a freeze attack.)
5. If the Timestamp and / or Snapshot keys have been rotated, delete the previous Timestamp and Snapshot metadata files. (Checks for recovery from fast-forward attacks {{MERCURY}}.)

#### How to check Timestamp metadata {#check_timestamp}

1. Download up to Y number of bytes. The value for Y is set by the implementor. For example, Y may be tens of kilobytes. The filename used to download the Timestamp metadata file is of the fixed form FILENAME.EXT (e.g., timestamp.json).
2. Check that it has been signed by the threshold of keys specified in the latest Root metadata file. If the new timestamp metadata file is not properly signed, discard it, abort the update cycle, and report the signature failure. (Checks for an arbitrary software attack.)
3. Check that the version number of the previous Timestamp metadata file, if any, is less than or equal to the version number of this Timestamp metadata file. If the new Timestamp metadata file is older than the trusted Timestamp metadata file, discard it, abort the update cycle, and report the potential rollback attack. (Checks for a rollback attack.)
4. Check that the latest attested time is lower than the expiration timestamp in this Timestamp metadata file. If the new Timestamp metadata file has expired, discard it, abort the update cycle, and report the potential freeze attack. (Checks for a freeze attack.)


#### How to check Snapshot metadata {#check_snapshot}

1. Download up to the number of bytes specified in the Timestamp metadata file, constructing the metadata filename as defined in {{metadata_filename_rules}}.
2. The hashes and version number of the new Snapshot metadata file MUST match the hashes and version number listed in Timestamp metadata. If the hashes and version number do not match, discard the new Snapshot metadata, abort the update cycle, and report the failure. (Checks for a mix-and-match attack.)
3. Check that it has been signed by the threshold of keys specified in the latest Root metadata file. If the new Snapshot metadata file is not signed as required, discard it, abort the update cycle, and report the signature failure. (Checks for an arbitrary software attack.)
4. Check that the version number of the previous Snapshot metadata file, if any, is less than or equal to the version number of this Snapshot metadata file. If this Snapshot metadata file is older than the previous Snapshot metadata file, discard it, abort the update cycle, and report the potential rollback attack. (Checks for a rollback attack.)
5. Check that the version number listed by the previous Snapshot metadata file for each Targets metadata file is less than or equal to the its version number in this Snapshot metadata file. If this condition is not met, discard the new Snapshot metadata file, abort the update cycle, and report the failure. (Checks for a rollback attack.)
6. Check that each Targets metadata filename listed in the previous Snapshot metadata file is also listed in this Snapshot metadata file. If this condition is not met, discard the new Snapshot metadata file, abort the update cycle, and report the failure. (Checks for a rollback attack.)
7. Check that the latest attested time is lower than the expiration timestamp in this Snapshot metadata file. If the new Snapshot metadata file is expired, discard it, abort the update cycle, and report the potential freeze attack. (Checks for a freeze attack.)

#### How to check Targets metadata {#check_targets}

1. Download the number of bytes either specified in the Snapshot metadata file, or some Z number of bytes, constructing the metadata filename as defined in {{metadata_filename_rules}}. The value for Z is set by the implementor. For example, Z may be tens of kilobytes.
2. The hashes (if any), and version number of the new Targets metadata file MUST match the latest Snapshot metadata. If the new Targets metadata file does not match, discard it, abort the update cycle, and report the failure. (Checks for a mix-and-match attack.) Skip this step if checking Targets metadata on a partial-verification ECU; partial-verification ECUs will not have Snapshot metadata.
3. Check that it has been signed by the threshold of keys specified in the relevant metadata file (Checks for an arbitrary software attack):
    1. If checking top-level targets metadata, the threshold of keys is specified in the Root metadata.
    2. If checking delegated targets metadata, the threshold of keys is specified in the targets metadata file that delegated authority to this role.
4. Check that the version number of the previous Targets metadata file, if any, is less than or equal to the version number of this Targets metadata file. (Checks for a rollback attack.)
5. If this Targets metadata file indicates that the Timeserver key should be rotated, then reset the clock used to determine the expiration of metadata to a minimal value (e.g. zero, or any time that is guaranteed to not be in the future based on other evidence). It will be updated in the next cycle.
6. Check that the latest attested time is lower than the expiration timestamp in this Targets metadata file. (Checks for a freeze attack.)
7. If checking targets metadata from the Director repository, verify that there are no delegations.
8. If checking targets metadata from the Director repository, check that no ECU identifier is represented more than once.

#### How to resolve delegations {#resolve_delegations}

To properly check targets metadata for an image, an ECU MUST locate the metadata file(s) for the role (or roles) that have the authority to sign the image. This metadata might be located in the top-level targets metadata, but it also may be delegated to another role--or to multiple roles. Therefore, all delegations MUST be resolved using the following recursive procedure, beginning with the top-level targets metadata file. (Note: "Stack" here is used as defined in RFC TODO.)

1. Add the current targets metadata file to the stack, and check it following the procedure in {{check_targets}}. If the file cannot be loaded, or if any verification step fails, abort the search, and indicate that image metadata cannot be found because of a missing or invalid role.
2. If the current metadata file contains signed metadata about the image, end the search and return the metadata to be checked.
3. If the current metadata file was reached via a terminating delegation and does not contain signed metadata about the image, abort the delegation resolution for this image and return an error indicating that image metadata could not be found.
4. Search the list of delegations, in listed order. For each delegation:
    1. Check if the delegation applies to the image being processed. For the delegation to apply, it MUST include the hardware identifier of the target, and the target name must match one of the delegation's image paths. If either of these tests fail, skip this delegation.
    2. If the delegation is a multi-role delegation, follow the procedure described in {{multirole_delegations}}. If the multi-role delegation is terminating and no valid image metadata is found, abort the delegation resolution and return an error indicating that image metadata could not be found.
    3. If the delegation is a normal delegation, add it to the stack and perform delegation resolution starting at step 1.
    4. If the end of the list of delegations is reached without finding valid image metadata, go back to the next-highest metadata file in the stack and continue searching its list of delegations. If there are no more files in the stack (i.e. if the end of the delegations list in the top-level targets metadata file is reached), return an error indicating that image metadata could not be found.

#### Multi-role delegations {#multirole_delegations}

It is possible to delegate signing authority to multiple delegated roles as described in {{TAP-3}}. Each multi-role delegation effectively contains a list of ordinary delegations, plus a threshold of those roles that must be in agreement about the non-custom metadata for the image. All multi-role delegations MUST be resolved using the following procedure. Note that there may be sub-delegations inside multi-role delegations.

1. For each of the roles in the delegation, find and load the image metadata (or error) following the procedure in {{resolve_delegations}}.
2. Inspect the non-custom part of the metadata loaded in step 1:
    1. Locate all sets of roles which have agreeing (i.e. identical) non-custom metadata. Discard any set of roles with a size smaller than the threshold of roles that must be in agreement for this delegation.
    2. Check for a conflict. A conflict exists if there remains more than one agreeing set of roles, each set having different metadata. If a conflict is found, choose and return the metadata from the set of roles which includes the earliest role in the multi-delegation list.
    3. If there is no conflict, check if there is any single set of roles with matching non-custom metadata. If there is, choose and return the metadata from this set.
    4. If no agreeing set can be found that meets the agreement threshold, return an error indicating that image metadata could not be found.

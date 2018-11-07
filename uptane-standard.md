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
  IN-TOTO:
    target: https://in-toto.github.io/
    title: "in-toto: A framework to secure the integrity of software supply chains"
    date: 2018-10-29


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
*Suppliers*: Independent companies to which auto manufacturers may outsource the production of ECUs. Tier-1 suppliers directly serve the manufacturers. Tier-2 suppliers are those that perform outsourced work for Tier-1 suppliers.  
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

TODO

### Use Cases

TODO

## Exceptions

To DO

## Out of Scope

The following topics will not be addressed in this document, as they represent threats outside the scope of Uptane:

* Physical attacks, such as manual tampering with ECUs outside the vehicle.
* Compromise of the supply chain (e.g., build system, version control system, packaging process). A number of strategies already (e.g., git signing, TPMs, in-toto {{IN-TOTO}}) exist to address this problem. Therefore, there is no need duplicate those techniques here.
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

Metadata files on a repository SHOULD be written using the ASN.1 abstract syntax specified in this section.  These files MAY be encoded and decoded using any transfer syntax that an OEM desires (e.g., BER, CER, DER, JSON, OER, PER, XER).

### Common Metadata Structures and Formats

Metadata files SHOULD share the data structures in this section. These data structures specify how information, such as cryptographic hashes, digital signatures, and public keys, should be encoded.

This is an ABNF module that defines common data structures used by metadata files.

```
RoleType        = "root" / "targets" / "snapshot" / "timestamp"

; String types.
Filename        = 1*32VCHAR
; No known path separator allowed in a strict filename.
StrictFilename  = %x21-2E / %x30-5B / %x5D-7E
BitString       = 1*1024BIT
OctetString     = 1*1024OCTET
HexString       = 1*1024HEXDIG
; Table 1 of RFC 4648.
Base64String    = 1*1024(ALPHA / DIGIT / "+" / "=" / "/")
; Adjust length to your needs.
Paths           = 1*8(Path)
Path            = 1*32((ALPHA / "_" / "*" / "\"" / "/"))
; Adjust length to your needs.
URLs            = *8URL
URL             = 1*1024VCHAR
; A generic identifier for vehicles, primaries, secondaries.
Identifier      = 1*32VCHAR

Natural         = *DIGIT
Positive        = *("1" / "2" / "3" / "4" / "5" / "6" / "7" / "8" / "9")
Length          = Positive
Threshold       = Positive
Version         = Positive
; The date and time in UTC encoded as a UNIX timestamp.
UTCDateTime     = Positive

BinaryData      = BitString / OctetString / HexString / Base64String

; Adjust length to your needs.
Hashes          = 1*8Hash
Hash            = HashFunction  BinaryData

HashFunction    = "sha224" / "sha256" / "sha384" / "sha512" / "sha512-224" /
                               "sha512-256" / ...

; Adjust length to your needs.
Keyids          = 1*8Keyid
; Usually, a hash of a public key.
Keyid           = HexString

; Adjust length to your needs.
Signatures      = 1*8Signature
Signature       = Keyid SignatureMethod Hash HexString
SignatureMethod = "rsassa-pss" / "ed25519" / ...

; Adjust length of SEQUENCE OF to your needs.
PublicKeys      = 1*8PublicKey
PublicKey       = Keyid PublicKeyType BinaryData
PublicKeyType   = "rsa" / "ed25519" / ...

```
An OEM MAY use any hash function (`Hash.function`; e.g., SHA-2) and signature scheme (`Signature.method`; e.g., [RSASSA-PSS](https://tools.ietf.org/html/rfc3447#page-29), [Ed25519](https://ed25519.cr.yp.to/)).

A hash digest (`Hash.digest`), signature (`Signature.sig`), or public key (`PublicKey.keyval`) SHOULD be encoded as either a bit, octet, hexadecimal, or Base64 string. For example, an RSA public key MAY be encoded using the PEM format, whereas an Ed25519 public key MAY be encoded as a hexadecimal string.

Every public key has a unique identifier (`PublicKey.keyid`). This identifier MAY be, for example, the SHA-256 hash of the public key.

An ECU SHOULD verify that each `Keyids`, `Hashes`, `Signatures`, and `PublicKeys` sequence contains unique `KeyId`, `Hash.function`, `Signature.keyid`, and `PublicKey.keyid` values, respectively. The ECU MAY reject a sequence containing duplicate values, or simply ignore such values.

Every metadata file contains three parts: a signed message (`Signed`), the number of signatures on the following message (`Length`), and a sequence of signatures for the message (`Signatures`).

The signed message is a sequence of four attributes: (1) `RoleType`, an enumerated type of the metadata (i.e., root, targets, snapshot, or timestamp), (2) `UTCDateTime`, an expiration date and time for the metadata (specified using the ISO 8601 format), (3) `Positive`, a positive version number, and (4) `SignedBody`, the role-specific metadata. The version number SHOULD be incremented every time the metadata file is updated. The attributes of role-specific metadata will be discussed in the rest of this section.

Signatures SHOULD be computed over the hash of the signed message, instead of the signed message itself.

Below is an example of the metadata format common to all metadata. All metadata SHOULD follow this format.
```
Metadata      = Signed Length Signatures
Expires       = UTCDateTime
Version       = Positive
Signed        = RoleType Expires Version SignedBody
SignedBody    = RootMetadata / TargetsMetadata / SnapshotMetadata / TimestampMetadata
```

### Root Metadata {#root_meta}

The root metadata distributes and revokes the public keys of the top-level root, targets, snapshot, and timestamp roles. These keys are revoked and replaced by changing the public keys specified in the root metadata. This metadata is signed using the root role’s private keys.

The root metadata contains two important attributes. First, the `keys` attribute lists the public keys used by the root, targets, snapshot, and timestamp roles. Second, the `roles` attribute maps each of the four roles to: (1) the URL pointing to its metadata file, (2) its public keys, and (3) the threshold number of keys required to sign the metadata file. An empty sequence of URLs denotes that the metadata file SHALL NOT be updated. An ECU SHOULD verify that each of the four roles has been defined exactly once in the metadata.

Here is the ABNF definition for the body of the root metadata.
```
; https://tools.ietf.org/html/rfc6025#section-2.4.2
NumberOfKeys  = Length
NumberOfRoles = Length
RootMetadata  = NumberOfKeys PublicKeys NumberOfRoles TopLevelRoles

; Adjust length to your needs.
TopLevelRoles = 4(TopLevelRole)
NumberOfURLs  = Length ; TAP 5: URLs pointing to the metadata file for this role.
NumberOfKeyIds = Length
TopLevelRole  = RoleType [NumberOfURLs] [URLs] NumberOfKeyIds Keyids Threshold
```

### Targets Metadata {#targets_meta}

At a minimum, a targets metadata file contains metadata (i.e., filename, hashes, length) about unencrypted images on a repository. The file MAY also contain two optional pieces of information: (1) custom metadata about which images should be installed by which ECUs, and whether encrypted images are available, and / or (2) other delegated targets roles that have been entrusted to sign images. This file is signed using the private keys of either the top-level targets role or a delegated targets role.

The following example specifies all of the REQUIRED as well as all of the RECOMMENDED attributes for the body of targets metadata.
```
Number of Targets  = Natural ; Allowed to have no targets at all.
TargetsMetadata    = NumberOfTargets Targets [TargetsDelegations] ; https://tools.ietf.org/html/rfc6025#section-2.4.2

; Adjust length to your needs.
Targets           = 1*128(TargetAndCustom)
TargetAndCustom   = Target [Custom]
NumberOfHashes    = Length
Target            = URL Filename Length NumberOfHashes Hashes

; The release counter is used to prevent rollback attacks on images when
; only the director repository is compromised.
; Every ECU should check that the release counter of its latest image is
; greater than or equal to the release counter of its previous image.
ReleaseCounter = Natural

; The hardware identifier is used to prevent the director repository,
; when it is compromised, from choosing images for an ECU that were not
; meant for it.
; Every ECU should check that the hardware ID of its latest image matches
; its hardware ID.
; An OEM MAY define other types of information to further restrict the
; choices that can be made by a compromised director repository.
HardwareIdnetifier = Identifier

; The ECU identifier specifies information, e.g., serial numbers, that the
; director uses to point ECUs as to which images they should install.
; Every ECU should check that the ECU ID of its latest image matches its
; own ECU ID.
EcuIdentifier = Identifier

; This attribute MAY be used by the director to encrypt images per ECU.
EncryptedTarget = Target

; This attribute is used to specify additional information, such as which
; images should be installed by which ECUs, and metadata about encrypted
; images.
; NOTE: The first 2 attributes are specified by both the image and
; director repositories.
; NOTE: The remaining attributes are specified only by the director
; repository.
Custom = [ReleaseCounter] [HardwareIdentifier] [EcuIdentifier] [EncryptedTarget] [EncryptedSymmetricKey]

; This is the symmetric key encrypted using the asymmetric ECU key.
EncryptedSymmetricKeyValue = BinaryData

; This attribute MAY be used if ECU keys are asymmetric, and a per-image
; symmetric encryption key is desired for faster decryption of images.
; In that case, the director would use the asymmetric ECU key to encrypt
; this symmetric key.
EncryptedSymmetricKey = EncryptedSymmetricKeyType EncryptedSymmetricKeyValue

EncryptedSymmetricKeyType = "aes128" / "aes192" / "aes256" / ...

; The public keys of all delegatees.
NumberOfKeys = Length

; The role name, filename, public keys, and threshold of a delegatee.
NumberOfDelegations = Length

; A list of paths to roles, listed in order of priority.
Delegations = PrioritizedPathsToRoles

TargetsDelegations  = NumberOfKeys PublicKeys NumberOfDelegations Delegations

; Adjust length to your needs.
PrioritizedPathsToRoles = 1*8(PathsToRoles)

; A list of image/target paths entrusted to these roles.
NumberOfPaths = Length

; A list of roles required to sign the same metadata about the matching
; targets/images.
NumberOfRoles = Length

; Whether or not this delegation is terminating.
; BIT simulates a boolean value
Terminating = BIT

PathsToRoles = NumberOfPaths Paths NumberOfRoles MultiRoles Terminating

; Adjust length to your needs.
MultiRoles = 1*8(MultiRole)
MultiRole = Rolename NumberOfKeyids Keyids Threshold

; The rolename (e.g., "supplierA-dev").
; No known path separator allowed in a rolename.
RoleName = StrictFilename

; The public keys used by this role.
NumberOfKeyids = Length
```

#### Metadata about Images

At the very least, a targets metadata file MUST contain the `TargetsMetadata.targets` attribute, which specifies a sequence of unencrypted images. An empty sequence is used to indicate that no targets/images are available. For every unencrypted image, its filename, version number, length, and hashes are listed using the `Target` sequence. An ECU SHOULD verify that each unencrypted image has been defined exactly once in the metadata file.

The unencrypted image SHOULD also be associated with additional information using the `Custom` sequence. The following attributes SHOULD be specified by both the image and director repositories. The `Custom.releaseCounter` attribute is used to prevent rollback attacks when the director repository is compromised. The director repository cannot choose images for an ECU with a release counter that is lower than the release counter of the image it has currently installed. The `Custom.hardwareIdentifier` attribute is used to prevent a compromised director repository from causing ECUs to install images that were not intended for them. For example, this attribute MAY be the ECU part number. The OEM and its suppliers MAY define other attributes that can be used by ECUs to further restrict which types of images they are allowed to install.

The following attributes SHOULD be specified by the director repository. The `Custom.ecuIdentifier` attribute specifies the identifier (e.g., serial number) of the ECU that should install this image. An ECU SHOULD verify that each ECU identifier has been defined exactly once in the metadata file. If the director repository wishes to publish per-ECU encrypted images, then the `Custom.encryptedTarget` attribute MAY be used to specify metadata about the encrypted images. An ECU MUST then download the encrypted image, check its metadata, decrypt the image, and check its metadata again. Finally, if an ECU key is an asymmetric public key, the director repository MAY use a *symmetric* private key to reduce the time used to decrypt the image. To do so, the director repository MAY use the *asymmetric* ECU key to encrypt, e.g., a private AES symmetric key, and place the encrypted key in the `Custom.encryptedSymmetricKey` attribute.


#### Metadata about Delegations {#delegations_meta}

Besides directly signing metadata about images, the targets role MAY delegate this responsibility to delegated targets roles. To do so, the targets role uses the OPTIONAL `TargetsMetadata.delegations` attribute. If this attribute is not used, then it means that there are no delegations.

The `TargetsDelegations.keys` attribute lists all of the public keys used by the delegated targets roles in the current targets metadata file. An ECU SHOULD verify that each public key (identified by its `Keyid`) has been defined exactly once in the metadata file.

The `TargetsDelegations.delegations` attribute lists all of the delegations in the current targets metadata file.  All delegations are prioritized: a sequence is used to list delegations in order of appearance, so that the earlier the appearance of a delegation, the higher its priority. Every delegation contains three important attributes.

The `PathsToRoles.paths` attribute describes a sequence of target/image paths that the delegated roles are trusted to provide. A desired target/image needs to match only one of these paths for the delegation to apply. A path MAY be either to a single file, or to a directory to indicate all files and / or subdirectories under that directory. A path to a directory is used to indicate all possible targets sharing that directory as a prefix; e.g. if the directory is "targets/A," then targets which match that directory include "targets/A/B.img" and "targets/A/B/C.img."

The `PathsToRoles.roles` attribute describes all of the roles that SHALL sign the same non-custom metadata (i.e., filename, length, and hashes of unencrypted images) about delegated targets/images. Every delegated targets role has (1) a name, (2) a set of public keys, and (3) a threshold of these keys required to verify its metadata file.

Note that a role name SHOULD follow the filename restrictions of the underlying file storage mechanism. For example, it may be “director” or "targets/director." As discussed in Section 3.7, the role name will determine part of the actual metadata filename of the delegated targets role. If it is “director” or “targets/director,” then its delegated targets metadata file MAY use the filename “director.ext” or “targets/director.ext,” respectively. However, the role name SHALL NOT use the path separator (e.g., “/” or “\”) if it is a character used to separate directories on the underlying file storage mechanism. In other words, all targets metadata files are implicitly assumed to reside in the same directory. It is safe to use this character in key-value databases or stores that do not have a notion of directories (e.g., Amazon S3).

Finally, the `PathsToRoles.terminating` attribute determines whether or not a backtracking search for a target/image should be terminated.

The metadata file for a delegated targets role SHALL have exactly the same format as for the top-level targets role. For example, the metadata file for a supplier role has precisely the same format as the the top-level targets role.

### Snapshot Metadata {#snapshot_meta}

The snapshot metadata lists the version numbers of all targets metadata files on the repository. It is signed using the snapshot role keys, and follows the format specified here.
```
; Adjust length to your needs.
SnapshotMetadata              = NumberOfSnapshotMetadataFiles SnapshotMetadataFiles
NumberOfSnapshotMetadataFiles = Length
SnapshotMetadataFiles         = 1*128SnapshotMetadataFile
SnapshotMetadataFile          = StrictFilename Version
; https://tools.ietf.org/html/rfc6025#section-2.4.2
```
The `filename` attribute specifies a metadata file's relative path from the metadata root of a repository, and SHALL NOT contain a path separator.

An ECU SHOULD verify that each filename has been defined exactly once in the snapshot metadata file.

### Timestamp Metadata {#timestamp_meta}

The timestamp metadata specifies metadata (e.g., filename and version number) about the snapshot metadata file. It is signed using the timestamp role keys, and follows the format below.
```
; https://tools.ietf.org/html/rfc6025#section-2.4.2
TimestampMetadata = Filename Version Length NumberOfHashes Hashes
NumberOfHashes = Length
```

### The map file

The map file specifies which images should be downloaded from which repositories. In most deployment scenarios for full verification ECUs, this will mean downloading images from both the image and director repositories. It is not signed, and follows the format specified here.
```
; https://github.com/theupdateframework/taps/blob/master/tap4.md
MapFile = NumberOfRepositories  Repositories NumberOfMappings Mappings

; A list of repositories
numberOfRepositories = Length

; A list of mapping of images to repositories.
NumberOfMappings = Length

; Adjust length to your needs.
Repositories    = 2Repository
; https://tools.ietf.org/html/rfc6025#section-2.4.2
Repository      = RepositoryName NumberOfServers Servers  

; Adjust length to your needs.
RepositoryNames = 2RepositoryName
; A shorthand name for the repository, which also specifies the name of the
; directory on the client which contains previous and latest metadata.
RepositoryName  = StrictFilename

; A list of servers where metadata and targets may be downloaded from.
NumberOfServers = Length
Servers         = URLs

; Adjust length to your needs.
Mappings = Mapping
; https://tools.ietf.org/html/rfc6025#section-2.4.2
Mapping  = NumberOfPaths Paths NumberOfRepositories RepositoryNames Terminating

; The list of targets delegated to the following repositories.
NumberOfPaths = Length  

; The repositories which MUST all sign the preceeding targets.
NumberOfRepositories = Length

; Whether or not this delegation is terminating.
; Simulate a BOOLEAN
Terminating = BIT

END
```
The `MapFile.repositories` attribute specifies a list of available repositories. For each repository, a short-hand name, and a list of servers where metadata and targets may be downloaded from, are specified. The short-hand name also specifies the metadata directory on an ECU containing the previous and current sets of metadata files.

The `MapFile.mappings` attribute specifies which images are mapped to which repositories. An OEM MAY map the same set of images to multiple repositories. Typically, an OEM would map all images to both the image and director repositories. See the deployment considerations document for other configurations, especially with regard to fleet management.

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

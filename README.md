
# HelloID-Conn-Prov-Target-Iprotect

| :warning: Warning |
|:---------------------------|
| Note that this is a complex connector. Please contact Tools4ever before implementing this connector! |

| :warning: Warning |
|:---------------------------|
| Note that this connector is "a work in progress" and therefore not ready to use in your production environment. |

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

<p align="center">
  <img src="assets/logo.png">
</p>

## Table of contents

- [Introduction](#Introduction)
- [Release notes](#Release-Notes)
- [Getting started](#Getting-started)
  + [Connection settings](#Connection-settings)
  + [Prerequisites](#Prerequisites)
  + [Remarks](#Remarks)
- [Setup the connector](#Setup-The-Connector)
- [Getting help](#Getting-help)
- [HelloID Docs](#HelloID-docs)

## Introduction

_HelloID-Conn-Prov-Target-Iprotect_ is a _target_ connector. Iprotect provides an XMLSQL interfase over https, That allows you to programmatically interact with it's data. The HelloID connector uses the API endpoints listed in the table below.

| Endpoint     | Description |
| ------------ | ----------- |
| https://`<ip`>:`<port`>/Webcontrols/xmlsql| Session cookie and all sql calls
| https://`<ip`>:`<port`>/Webcontrols/j_security_check | Session login

## Release notes
Version 2.0.0

This is a complete overhaul of the previous connector.
It is not compatible with the previous version.

Main Changes are:
1) No longer uses the xml-import interface for the create, update and delete of accounts, but the genera xmlsql interface instead.
2) Implemented the management of Accesskeys and Licenseplates in the user cycle actions.


## Getting started

### Connection settings

The following settings are required to connect to the API.

| Setting      | Description                        | Mandatory   |
| ------------ | -----------                        | ----------- |
| UserName     | The UserName to connect to the API | Yes         |
| Password     | The Password to connect to the API | Yes         |
| BaseUrl      | The URL to the API ( https://`<ip`>:`<port`>/Webcontrols) | Yes         |

### Prerequisites

An Iprotect account ("systeemgebruiker") must be created with sufficient rights to query and update the employees and accesskeys
Make sure that the box "synchronisatie beheerder" is checked in the "detail systeemgebruiker", and that the account has sufficient rights to query and update the iprotect database

To verify this: login into the web GUI  with a browser of iprotect with this account and check
1.  The ability to successfully query the accesskey, employee and user tables with this account


### Remarks
- Only NLD License Plates are supported by default. Unless there is a proper mapping for the country code, the lookup for license plates from different countries fails.
- The CardClassId that defines the kind of an accesskey may differ between IProtect implementations. These are hardcoded in the Initialization section in the scripts. Default they are '2' for general access keys, and '6' for "license plates".
- The connector manages exactly one AccessKey per HelloID Person.
- The currently assigned Accesskeys with a different RCN than provided by HelloID are ignored and stay unmanaged from HelloID. Except for the license plates, these are managed in a separate flow.
- Make sure that the AccessKeyRCN that is provided when creating a new account is fully padded (so '000001' instead of '1'.  The RCN may be automatically padded by Iprotect otherwise, which causes lookup errors.
- The licence plate is Optional and always created as valid (active)
- The valid property of the accesskey that is managed by HelloId is modified in the Disable and Enable Actions. By default unmanaged accesskeys are not modified.
- The update action does not revoke AccessKeys because the accessKey is required and other HelloID actions depend on the reference. The access keys will be revoked in the delete script.
- The account create.ps1 creates an account and grants optional accesskey and/or a license plate.
- The accessKey is a standalone object in Iprotect and must be connected to an Employee account. The accessKey is required for the user life cycle and the permission (KeyGroups). So you must create a Custom complex property in the source mapping, which makes it possible to check in the business rules if a IProtect account has an AccessKey. _Person.Custom.HasAccesskey_. You can now create a Business Rule that makes it possible to make the disable/enable script and the permission scripts dependend hereof, so these actions do not get triggerd if the Iprotect account does have an accesskey linked.
- The Enable and the Disable script grants and revokes the accesskey linked to a user account in Iprotect and not the account itself. An Account object does not have some sort of an active property.


## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required.

Create Custom Properties in HelloID
 - Person.Custom.AccessKeyID
 - Person.Custom.LicensePlate
 - Person.Custom.HasAccesskey    (Required for the businessRules)
 - Person.Custom.HasLicensePlate (Required for the businessRules)

Note! The custom properties HasAccessKey and HasLicensePlate are required for the business rules, so you can create a dependency for the KeyGroups.

- HelloID session management must be configured so that only one action at a time is allowed. This is because a logout action may logout all connected sessions.
- The connector should be run from a local povisioning agent.

## Description of the available ps1 scripts\

### Create.ps1
 - Creates or correlates a new employee. Expects the salaryNR as the ExternalID used for the correlation.

 - On a create of the employee, uses the provided $account.PersonName and $account.PersonFirstName to create or correlate the associated user object.

 - On a Correlate of the employee, uses the provided $account.PersonName and $account.PersonFirstName to verify that the employee account does belong to the specified user. Will generate an error if they do not match.

 - if the flag $updatePerson is given,  properties of the account will be updated for existing accounts. (they are always updated/set for new accounts). This includes the Accesskey and Licenseplate when provided.

 - Expects the salaryNR as the ExternalID for the person, and the $account.PersonName and the GivenName of the person as required parameters.

 - Produces as Accountreference an object with the following 4 fields: EmployeeId,PersonId,AccessKeyId,AccessKeyIdLicensePlate

    Note that this are internal IDs of iprotect.

### Update.ps1
- Updates the properties of the account. Can be used to assign a new accesskey or licenseplate to an account (if the account does not have one already), or to update the RCN of an existing one (when the account does already have one).

 Note, it cannot be used to remove a standard accesskey association from an account.

### Delete.ps1
- Removes the link to the person from the managed Accesskey and licenseplates, and then deletes the employee and its associated person object.

  Note, it is assumed that keygroup memberschips are already removed by Helloid prior of running this script.

  Note, if there are still unmanaged accesskeys on the account, the deletion of the Person associated with the account may fail.

### Enable.ps1
- Sets the "VALID" property of the Accesskey of the account to true.

### Disable.ps1
-  Sets the "VALID" property of the Accesskey of the account to false.

### Entitlements.ps1
- Retrieves the keyGroups.

### Grant.ps1
- Assigns the managed Accesskey of the account to the specified keygroup.

### Revoke.ps1
- Removes the managed Accesskey of the account from the specified keygroup.


## Available api documentation (included in this repo for info)

1. "iProtect API v2.10.doc   Description of the xmlsql api, used for generic sql queries and updates
2. "Jdbc handleiding v0.3.pdf"   Some info regarding the (limitiations of) the supported sql

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/

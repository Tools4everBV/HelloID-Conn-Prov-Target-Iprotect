
# HelloID-Conn-Prov-Target-Iprotect

> [!WARNING]
> Note that this is a complex connector. Please contact Tools4ever before implementing this connector!

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Iprotect/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Iprotect](#helloid-conn-prov-target-iprotect)
  - [Table of contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Remarks](#remarks)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Provisioning PowerShell V2 connector](#provisioning-powershell-v2-connector)
      - [Correlation configuration](#correlation-configuration)
      - [Field mapping](#field-mapping)
    - [Connection settings](#connection-settings)
  - [Setup the connector](#setup-the-connector)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Prerequisites
- [ ] _HelloID_ on-prem Provisioning agent (due to IP filtering and restrictions).
- [ ] _HelloID_ environment.
- [ ] Ensure that an iProtect account ("systeemgebruiker") is created with adequate permissions for querying and updating employee information and access keys.
  - [ ] Confirm that the "synchronisatie beheerder" option is selected in the "detail systeemgebruiker" settings.
  - [ ] Verify that the account possesses the necessary privileges to interact with and modify the iProtect database.
- [ ] **Concurrent sessions** in HelloID set to a **maximum of 1**! Exceeding this limit may result in timeout or session errors, as a logout action may terminate all connected sessions.

To verify this:
1. Log in to the iProtect web GUI using a browser with the provided account credentials.
2. Confirm the ability to successfully query the accesskey, employee, and user tables using this account.

## Remarks
- This connector efficiently manages multiple objects within each script. For instance, during the create action, it handles the creation of a person, employee, key card, and license plate.
- By default, only NLD license plates are supported. Without proper mapping for other country codes, the lookup for license plates from different countries will fail.
- The CARDCLASSID, defining the type of access key, may vary across iProtect implementations and is hardcoded in the mapping. Typically, '2' signifies "general access keys", and '6' indicates "license plates."
- The connector manages exactly one access key (of each type) per HelloID Person.
- Access keys currently assigned with a different RCN than provided by HelloID are ignored and remain unmanaged in HelloID, except for license plates, which are handled separately.
- Ensure that the AccessKeyRCN provided when creating a new account is fully padded (e.g., '000001' instead of '1'). If not properly padded, iProtect may automatically pad the RCN, leading to lookup errors.
- License plates are optional and always created as valid (active).
- The 'valid' property of the access key managed by HelloID is modified in the Disable and Enable Actions. By default, unmanaged access keys are not altered.
- The update action does not revoke AccessKeys because the accessKey is required, and other HelloID actions depend on the reference. Access keys will be revoked in the delete script.
- The account creation script (create.ps1) generates an account and optionally grants an access key and/or a license plate.
- The access key is a standalone object in iProtect and must be linked to an Employee account. It is essential for the user life cycle and permissions (KeyGroups). Therefore, create a custom complex property in the source mapping, such as Person.Custom.HasAccesskey. This enables checking in the business rules if an iProtect account has an access key linked. Consequently, you can create a Business Rule ensuring that the disable/enable script and permission scripts are dependent on this condition, preventing these actions from being triggered if the iProtect account lacks an access key.
- The Enable and Disable scripts grant and revoke the access key linked to a user account in iProtect, not the account itself, as an Account object does not possess an active property.

## Introduction

_HelloID-Conn-Prov-Target-Iprotect_ is a _target_ connector. Protect offers an XMLSQL interface over HTTPS, that allows you to programmatically interact with it's data. The HelloID connector uses the API endpoints listed in the table below.

| Endpoint                                             | Description                      |
| ---------------------------------------------------- | -------------------------------- |
| https://`<ip`>:`<port`>/Webcontrols/xmlsql           | Session cookie and all sql calls |
| https://`<ip`>:`<port`>/Webcontrols/j_security_check | Session login                    |

The following lifecycle actions are available:

| Action                            | Description                                                                                                                                                                          | Remarks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| create.ps1                        | 1. Create or correlate to a person.<br>2. Create or correlate to an employee.<br>3. Create, assign or correlate to a key card.<br>4. Create, assign or correlate to a license plate. |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| delete.ps1                        | 1. Delete key card.<br>2. Unassign (no delete!) license plate from person.<br>3. Delete employee.<br>4. Delete person.                                                               | Delete  key card consists of multiple actions:<br>1. Delete assigned groups of key card.<br>2. Delete offline access rights of key card.<br>3. Delete key card.                                                                                                                                                                                                                                                                                                                                                                         |
| enable.ps1                        | 1. Enable key card.<br>2. Enable license plate.                                                                                                                                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| disable.ps1                       | 1. Disable key card.<br>2. Disable license plate.                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| update.ps1                        | 1. Update person.<br>2. Update employee.<br>3. Either update new key card or delete old key card.<br>4. Either update new license plate or unassign (no delete!) old license plate.  | Update new key card consists of multiple actions:<br>1. Create new key card.<br>2. Assign permissions of old key card to new key card.<br>3. Delete permissions assigned groups of old key card.<br>4. Delete offline access rights of old key card.<br>5. Delete old key card.<br>6. Assign permissions of old key card to new key card.<br>Delete old key card consists of multiple actions:<br>1. Delete permissions assigned groups of old key card.<br>2. Delete offline access rights of old key card.<br>3. Delete old key card. |
| permissions.keyCard.ps1           | List keygroups, specifically for key card as permissions                                                                                                                             |
| grantPermission.keyCard.ps1       | Grant keygroup to key card                                                                                                                                                           |
| revokePermission.keyCard.ps1      | Revoke keygroup from key card                                                                                                                                                        |
| subPermissions.keyCard.ps1        | Dynamically grant and/or revoke keygroups to key card based on source field "Custom.iProtectGroups"                                                                                  |
| permissions.licensePlate.ps1      | List keygroups, specifically for license plate as permissions                                                                                                                        |
| grantPermission.licensePlate.ps1  | Grant keygroup to license plate                                                                                                                                                      |
| revokePermission.licensePlate.ps1 | Revoke keygroup from license plate                                                                                                                                                   |

## Getting started
By using this connector you will have the ability to create and manage persons, employees and access keys in iProtect. Additionally, you can grant or revoke keygroups for the access keys, enhancing your workflow. 

Connecting to iProtect is straightforward. Simply utilize the username and password.
For further details, refer to the iProtect documentation:
- For a description of the xmlsql api, used for generic sql queries and updates, see: [iProtect API v2.10](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Iprotect/blob/main/iProtect%20API%20v2.10.pdf)
- For some info regarding the (limitiations of) the supported sql[jdbc handleiding v0.3](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Iprotect/blob/main/jdbc%20handleiding%20v0.3.pdf)

### Provisioning PowerShell V2 connector

#### Correlation configuration
Due to managing multiple objects within a single connector, we do not utilize the built-in HelloID Correlation functionality. Instead, correlation is defined within the mapping configuration.

#### Field mapping

The field mapping can be imported by using the [_fieldMapping.json_](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Iprotect/blob/main/fieldMapping.json) file.

### Connection settings

The following settings are required to connect to the API.

| Setting      | Description                                                                       | Mandatory |
| ------------ | --------------------------------------------------------------------------------- | --------- |
| BaseUrl      | The URL to the API.                                                               | Yes       |
| UserName     | The username to connect to the API.                                               | Yes       |
| Password     | The password to connect to the API.                                               | Yes       |
| IsDebug      | When toggled, extra logging is shown. Note that this is only meant for debugging. | No        |
| ProxyAddress | When entered the proxy addressed will be used when connecting to the API.         | No        |

## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required.

Create Custom Properties in HelloID
 - Person.Custom.profitEmId (Used in correlation for the person)
 - Person.Custom.kaartnummer (Used in correlation key the access key)
 - Person.Custom.kenteken (Used in correlation key the license plate)
 - Person.Custom.HasAccesskey    (Required for the businessRules)
 - Person.Custom.HasLicensePlate (Required for the businessRules)

Note! The custom properties HasAccessKey and HasLicensePlate are required for the business rules, so you can create a dependency for the KeyGroups.

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/

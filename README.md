# HelloID-Conn-Prov-Target-IProtect

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

> [!WARNING]
> Note that this is a complex connector. Please contact your local Tools4ever sales representative for further information and details about the implementation of this connector

<p align="center">
  <img src="https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-Iprotect/refs/heads/main/Logo.png">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-IProtect](#helloid-conn-prov-target-iprotect)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
    - [Lifecycle scripts](#lifecycle-scripts)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Configuration options](#configuration-options)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account reference](#account-reference)
  - [Remarks](#remarks)
    - [Lookup Field Behavior](#lookup-field-behavior)
      - [Department Lookup](#department-lookup)
      - [Authorization Group Lookup](#authorization-group-lookup)
      - [FreeSelect Field Lookup](#freeselect-field-lookup)
    - [FREETEXT and FREESELECT Character Limits](#freetext-and-freeselect-character-limits)
    - [AccessKeys Not Managed](#accesskeys-not-managed)
    - [Employee and Person Account](#employee-and-person-account)
    - [Correlation on FirstName and (Last) Name](#correlation-on-firstname-and-last-name)
    - [Enable and Disable Linked AccessKey](#enable-and-disable-linked-accesskey)
    - [Delete Account with Removed Linked AccessKeys](#delete-account-with-removed-linked-accesskeys)
    - [Permission Grants and Revokes on AccessKeys](#permission-grants-and-revokes-on-accesskeys)
    - [SQL Queries](#sql-queries)
    - [Reboarding](#reboarding)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-IProtect_ is a _target_ connector. _IProtect_ provides a set of REST API's that allow you to programmatically interact with its data. This connector manages Person and Employee accounts in IProtect and their KeyGroup permissions.

## Supported features

The following features are available:

| Feature                             | Supported | Actions                                 | Remarks                                                                                   |
| ----------------------------------- | --------- | --------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Account Lifecycle**               | ✅         | Create, Update, Enable, Disable, Delete | Enable/Disable actions target linked AccessKeys, not the account itself. [Read more](#enable-and-disable-linked-accesskey) |
| **Permissions**                     | ✅         | Retrieve, Grant, Revoke                 | Permissions are granted/revoked on each linked AccessKey. [Read more](#permission-grants-and-revokes-on-accesskeys) |
| **Resources**                       | ✅         | -                                       |                                                                                           |
| **Entitlement Import: Accounts**    | ✅         | -                                       |                                                                                           |
| **Entitlement Import: Permissions** | ✅         | -                                       |                                                                                           |

### Lifecycle scripts

The following lifecycle scripts are included in the connector:

| Script                                  | Description                                                                                  |
| --------------------------------------- | -------------------------------------------------------------------------------------------- |
| create.ps1                              | Creates a new person and employee account.                                                   |
| delete.ps1                              | Removes an existing person and employee account, and removes the link of linked AccessKeys.  |
| disable.ps1                             | Disables an account, by disabling the linked AccessKeys. Sets the "VALID" property to false. |
| enable.ps1                              | Enables an account, by enabling the linked AccessKeys. Sets the "VALID" property to true.    |
| update.ps1                              | Updates the attributes of a person and employee account.                                     |
| import.ps1                              | Imports the account and linked AccessKeys.                                                   |
| permissions/groups/grantPermission.ps1  | Grants specific KeyGroup permissions to each Accesskey linked to the account.                |
| permissions/groups/revokePermission.ps1 | Revokes specific KeyGroup permissions from each Accesskey linked to the account.             |
| permissions/groups/permissions.ps1      | Retrieves all available keyGroups permissions.                                               |
| configuration.json                      | Contains the connection settings and general configuration for the connector.                |
| fieldMapping.json                       | Defines mappings between person fields and target system person account fields.              |

## Getting started

### HelloID Icon URL
URL of the icon used for the HelloID Provisioning target system.

```
https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-Iprotect/refs/heads/main/Icon.png
```

### Requirements

Before implementing this connector, ensure the following requirements are met:

**IProtect API Access:**

- An IProtect account ("systeemgebruiker") must be created with sufficient rights to query and update employees and AccessKeys
- The "Synchronisatie Beheerder" checkbox must be checked in the "Detail Systeemgebruiker" settings
- The account must have sufficient permissions to query and update the IProtect database
- To verify: Login to the IProtect web GUI with this account and confirm the ability to successfully query the accesskey, employee, and user tables

**HelloID Configuration:**

- **Local Agent**: The connector must be run from a local HelloID agent (cloud agent not supported)
- **Concurrent Sessions**: HelloID concurrent sessions must be set to a **maximum of 1**. This is required because a logout action in IProtect may terminate all connected sessions simultaneously
- **SubPermissions**: SubPermissions must be enabled in the KeyGroup permissions block configuration. This is required because permissions are granted to AccessKeys (not to Person/Employee accounts), and a single account can have multiple AccessKeys. The connector grants permissions to each AccessKey individually, requiring SubPermissions to track which AccessKey has which KeyGroup permission.

### Connection settings

The following settings are required to connect to the API.

| Setting  | Description                                               | Mandatory | Example                              |
| -------- | --------------------------------------------------------- | --------- | ------------------------------------ |
| UserName | The UserName to connect to the API                        | Yes       | `systeemgebruiker`                   |
| Password | The Password to connect to the API                        | Yes       | `(secret)`                           |
| BaseUrl  | The URL to the API ( https://`<ip`>:`<port`>/Webcontrols) | Yes       | `https://10.0.0.1:8443/Webcontrols` |

### Configuration options

The connector provides the following configuration options to control lookup behavior:

| Setting                           | Description                                                                                                                                           | Type  | Default | Options                                                              |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ------- | -------------------------------------------------------------------- |
| whenDepartmentNotFound            | Action to take when department lookup returns no results or empty value                                                                              | Radio | Error   | **Error**: Stop processing and generate error<br>**Clear**: Set department to null and continue |
| whenAuthorizationGroupNotFound    | Action to take when authorization group (HsId) lookup returns no results or empty value                                                              | Radio | Error   | **Error**: Stop processing and generate error<br>**Clear**: Set authorization group to null and continue |
| whenFreeSelectFieldNotFound       | Action to take when FreeSelect field lookup returns no results or empty value                                                                        | Radio | Error   | **Error**: Stop processing and generate error<br>**Clear**: Set FreeSelect field to null and continue |

> [!NOTE]
> These configuration options allow you to control how the connector handles missing or invalid lookup values. Choose **Error** to ensure data integrity by stopping when lookups fail, or **Clear** to allow accounts to be created/updated with null values in these fields.

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _IProtect_ to a person in _HelloID_.

| Setting                   | Value               |
| ------------------------- | ------------------- |
| Enable correlation        | `True`              |
| Person correlation field  | `ExternalId`        |
| Account correlation field | `Employee.SalaryNR` |

> [!NOTE]
> The connector uses a two-stage correlation approach. First, it attempts to correlate based on `Employee.SalaryNR`. If no Employee is found, it performs a secondary correlation on the Person object using `FirstName` and `Name` to prevent duplicate accounts. See [Correlation on FirstName and (Last) Name](#correlation-on-firstname-and-last-name) for more details.

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Account reference

The account reference is populated with a composite object containing:
- `PersonId` - The IProtect Person ID (returned after creation)
- `EmployeeId` - The IProtect Employee ID (returned after creation)

## Remarks

### Lookup Field Behavior

#### Department Lookup
- Map the `Person.DepartmentId` field with the **department name** (not the ID)
- The connector automatically looks up the department by name and converts it to the IProtect department ID
- **Special characters** (apostrophes and ampersands) are automatically escaped to prevent SQL errors
- Configure the `whenDepartmentNotFound` setting to control behavior when the department is not found

#### Authorization Group Lookup
- Map the `Person.HsId` or `Employee.HsId` fields with the **authorization group name** (not the ID)
- The connector automatically looks up the HsGroup by name and converts it to the IProtect HsGroup ID
- Configure the `whenAuthorizationGroupNotFound` setting to control behavior when the group is not found

#### FreeSelect Field Lookup
- Map `Person.FREESELECT{number}` fields (e.g., `Person.FREESELECT4`) with the **custom text value name** (not the ID)
- The connector automatically looks up the custom text value and converts it to the IProtect custom text ID
- Configure the `whenFreeSelectFieldNotFound` setting to control behavior when the value is not found
- **Character limit**: Maximum 40 characters (automatically truncated in field mapping examples)

> [!TIP]
> All lookup fields support special character escaping. Apostrophes are escaped as `\'` and ampersands as `&amp;` to ensure SQL query compatibility.

### FREETEXT and FREESELECT Character Limits

IProtect enforces a maximum character limit of 40 characters on both FREETEXT and FREESELECT fields. Values exceeding this limit will be rejected by IProtect.

> [!WARNING]
> Ensure values mapped to FREETEXT and FREESELECT fields do not exceed 40 characters. Use the `.substring(0, 40)` method in your field mapping to truncate values if needed. Values longer than 40 characters will cause errors during account creation or updates.

### AccessKeys Not Managed

The scope of the connector is to manage Persons and Employees, as well as perform grants, revokes, and enable or disable linked AccessKeys. However, managing AccessKeys—such as creating, updating, or linking them—is **NOT** in scope.

> [!WARNING]
> AccessKey management (creation, updates, linking) is not handled by this connector. When a person receives a new or additional AccessKey:
> - The AccessKey must be manually enabled in IProtect
> - Permissions should be manually copied from an existing AccessKey
> - The connector will not automatically apply permissions to newly linked AccessKeys

> [!NOTE]
> The only exception is the delete action, which automatically unlinks AccessKeys from the account. See [Delete Account with Removed Linked AccessKeys](#delete-account-with-removed-linked-accesskeys).

### Employee and Person Account

Although this connector manages Employees, we cannot ignore the Person object. This is a separate object within IProtect. An Employee object cannot exist without a Person object; however, the reverse is possible. The field mapping is divided into Person and Employee properties, with the connector code handling the rest.

> [!NOTE]
> The relationship between Person and Employee objects:
> - Every Employee must have a linked Person object
> - A Person can exist without an Employee
> - The connector manages both objects together
> - The linking key is `PersonId`

### Correlation on FirstName and (Last) Name
During correlation, the connector correlates based on the Employee.SalaryNR using a combined query to retrieve both the Person and Employee objects at once. Once this query returns a positive result, the account will be correlated. If no Employee is found, a separate query is performed to retrieve only the Person object based on `FirstName` and (Last) `Name` to avoid errors and duplicate accounts, and correlates the person account when one is found without a linked Employee.

### Enable and Disable Linked AccessKey

The Enable and Disable scripts target the AccessKeys linked to a user account in IProtect, not the account itself. Person and Employee objects do not have an active/enabled property.

> [!IMPORTANT]
> Enable/Disable behavior:
> - Enable sets the `VALID` property to `true` on all linked AccessKeys
> - Disable sets the `VALID` property to `false` on all linked AccessKeys
> - The Person and Employee account itself is not modified
> - Only AccessKeys that are linked at the time of enable/disable are affected
> - AccessKeys linked after "Account Access" is granted will not be automatically updated

### Delete Account with Removed Linked AccessKeys

Before deleting the Person and Employee, the Delete action first unlinks all linked AccessKeys.

> [!WARNING]
> Delete behavior and limitations:
> - All linked AccessKeys are automatically unlinked before account deletion
> - The connector does not remove unmanaged permissions from the AccessKey
> - Unlinked AccessKeys may still contain permissions from previous assignments
> - If the account has unmanaged AccessKeys that cannot be unlinked, the deletion may fail
> - Be cautious when linking previously used AccessKeys to new accounts, as they may retain old permissions

### Permission Grants and Revokes on AccessKeys

KeyGroup permissions are granted or revoked on each linked AccessKey of the IProtect account.

> [!IMPORTANT]
> Permission management behavior:
> - Permissions are applied to **each individual AccessKey** linked to the account, not to the Person or Employee
> - If no AccessKey is linked when granting a permission, the grant will fail and retry until an AccessKey is available
> - Newly linked AccessKeys after a permission grant will not automatically receive the permission
> - Best practice: When a person receives a new AccessKey, manually copy permissions from an existing AccessKey
> - To apply permissions to newly linked AccessKeys via HelloID, use the grant script as an update script and manually run "Force update permissions" in the definition

### SQL Queries
- The connector largely consists of SQL queries that are sent to the IProtect endpoints. There are some restrictions compared to standard SQL, which can be found in the documentation.
- The linking key between the Employee and Person objects is the `PersonId`.

### Reboarding
Reboarding an employee after they are deleted from HelloID is supported, with one side note. AccessKeys are automatically unlinked from the account during the delete action and will not be present when the employee is recreated.

## Development resources

### API endpoints

The following endpoints are used by the connector:

| Endpoint          | Method | Description                      |
| ----------------- | ------ | -------------------------------- |
| /xmlsql           | POST   | Session cookie and all sql calls |
| /j_security_check | POST   | Session login                    |

### API documentation

The IProtect API documentation is provided by the vendor:

- **iProtect API v2.10.doc** - Description of the xmlsql API, used for generic SQL queries and updates
- **Jdbc handleiding v0.3.pdf** - Information regarding the limitations of the supported SQL syntax

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/

# HelloID-Conn-Prov-Target-IProtect

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

> [!WARNING]
> Note that this is a complex connector. Please contact your local Tools4ever sales representative for further information and details about the implementation of this connector

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Iprotect/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-IProtect](#helloid-conn-prov-target-iprotect)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Available lifecycle actions](#available-lifecycle-actions)
    - [Field mapping](#field-mapping)
  - [Remarks](#remarks)
    - [AccessKeys Not Managed](#accesskeys-not-managed)
    - [Employee and Person Account](#employee-and-person-account)
    - [Correlation on FirstName and (Last) Name](#correlation-on-firstname-and-last-name)
    - [Uniqueness Check for Person Object (FirstName and (Last) Name)](#uniqueness-check-for-person-object-firstname-and-last-name)
    - [Enable and Disable Linked AccessKey](#enable-and-disable-linked-accesskey)
    - [Delete Account with Removed Linked AccessKeys](#delete-account-with-removed-linked-accesskeys)
    - [Permission Grants and Revokes on AccessKeys](#permission-grants-and-revokes-on-accesskeys)
    - [SQL Queries](#sql-queries)
    - [Reboarding](#reboarding)
  - [Development Resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-IProtect_ is a _target_ connector. _IProtect_ provides a set of REST API's that allow you to programmatically interact with its data.

Supported features:
| Feature                             | Supported | Actions                                 | Remarks |
| ----------------------------------- | --------- | --------------------------------------- | ------- |
| **Account Lifecycle**               | ✅         | Create, Update, Enable, Disable, Delete |         |
| **Permissions**                     | ✅         | Retrieve, Grant, Revoke                 |         |
| **Resources**                       | ✅         | -                                       |         |
| **Entitlement Import: Accounts**    | ✅         | -                                       |         |
| **Entitlement Import: Permissions** | ❌         | -                                       |         |

## Getting started

### Prerequisites

- **IProtect Permissions**:<br>
An IProtect account ("systeemgebruiker") must be created with sufficient rights to query and update the employees and AccessKeys
Make sure that the box "Synchronisatie Beheerder" is checked in the "Detail Systeemgebruiker", and that the account has sufficient rights to query and update the IProtect database.
- To verify this: login into the web GUI of IProtect with this account and check: The ability to successfully query the accesskey, employee and user tables with this account

- **Local Agent**:<br>
The connector should be run from a local agent.

- **Concurrent sessions**:<br>
Concurrent sessions in HelloID should be set to a **maximum of 1**! This is because a logout action may logout all connected sessions.

- **SubPermissions**:<br>
- Enable SubPermission to be able to see to which accessKeys the permissions are granted.

### Connection settings

The following settings are required to connect to the API.

| Setting  | Description                                               | Mandatory |
| -------- | --------------------------------------------------------- | --------- |
| UserName | The UserName to connect to the API                        | Yes       |
| Password | The Password to connect to the API                        | Yes       |
| BaseUrl  | The URL to the API ( https://`<ip`>:`<port`>/Webcontrols) | Yes       |

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _IProtect_ to a person in _HelloID_.

| Setting                   | Value               |
| ------------------------- | ------------------- |
| Enable correlation        | `True`              |
| Person correlation field  | `ExternalId`        |
| Account correlation field | `Employee.SalaryNR` |

> More information about `Employee` and `Person` correlation please refer to: [Correlation on FirstName and (Last) Name](#correlation-on-firstname-and-last-name)

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Available lifecycle actions

The following lifecycle actions are available:

| Action                                  | Description                                                                                  |
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

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

## Remarks
### AccessKeys Not Managed
- The scope of the connector is to manage Persons and Employees, as well as perform grants, revokes, and enable or disable linked AccessKeys. However, managing AccessKeys—such as creating, updating, or linking them—is **NOT** in scope.
- This also means that when a person receives a new or additional AccessKey, the AccessKey must be manually enabled, and the permissions should be copied from the existing key.
- With one exception, the linked AccessKey will be removed from the account during the delete action. See [Delete Account with Removed Linked AccessKeys](#delete-account-with-removed-linked-accesskeys).

### Employee and Person Account
Although this connector manages Employees, we cannot ignore the Person object. This is a separate object within IProtect. An Employee object cannot exist without a Person object; however, the reverse is possible. The field mapping is divided into Person and Employee properties, with the connector code handling the rest.

### Correlation on FirstName and (Last) Name
During correlation, the connector correlates based on the Employee.SalaryNR using a combined query to retrieve both the Person and Employee objects at once. Once this query returns a positive result, the account will be correlated. If no Employee is found, a separate query is performed to retrieve only the Person object based on `FirstName` and (Last) `Name` to avoid errors and duplicate accounts, and correlates the person account when one is found.

### Uniqueness Check for Person Object (FirstName and (Last) Name)
The uniqueness check ensures that the Person object is unique within the IProtect environment. The script validates the `personTable` for `FirstName` and (Last)`Name`. If an account is found, it checks whether an Employee account is linked. Only if an employee account is also found does the uniqueness check determine that the person object is **NOT** unique. If there is only a Person account without a linked Employee account, that Person account will be correlated.

### Enable and Disable Linked AccessKey
- The Enable and Disable scripts grant and revoke the AccessKey linked to a user account in IProtect, but not the account itself. An Account object does not have an active property.
- The connector does not update newly assigned AccessKeys that are linked after "Account Access" has been granted.

### Delete Account with Removed Linked AccessKeys
- Before deleting the Person and Employee, the Delete action first unlinks all linked AccessKeys.
- By unlinking the AccessKey from the account. The connector does not remove unmanaged permissions from the AccessKey, which means, in theory, that the unlinked AccessKey may still contain permissions. Keep this in mind when linking a previously used AccessKey to a new account.
- If there are still unmanaged AccessKeys on the account, the deletion of the Person associated with the account may fail.

### Permission Grants and Revokes on AccessKeys
- KeyGroup permissions are granted or revoked on each linked AccessKey of the IProtect account.
- If no linked AccessKey is present during the permission granting process, the grant script will result in an error and retry until an AccessKey is linked.
- The connector does not update newly assigned AccessKeys after the permission has been granted.
- The best practice should be when a person receives a new AccessKey the granted permissions are copied for an existing Key.
- To apply permissions to newly linked AccessKeys with HelloID, you can place the grant script asan update script and manually run "Force update permissions in the definition."

### SQL Queries
- The connector largely consists of SQL queries that are sent to the IProtect endpoints. There are some restrictions compared to standard SQL, which can be found in the documentation.
- The linking key between the Employee and Person objects is the `PersonId`.

### Reboarding
Reboarding an employee after they are deleted from HelloID is supported, with one side note. AccessKeys are automatically unlinked from the account during the delete action and will not be present when the employee is recreated.

## Development Resources

### API endpoints

The following endpoints are used by the connector

| Endpoint          | Description                      |
| ----------------- | -------------------------------- |
| /xmlsql           | Session cookie and all sql calls |
| /j_security_check | Session login                    |

### API documentation
- "iProtect API v2.10.doc   Description of the xmlsql api, used for generic sql queries and updates
- "Jdbc handleiding v0.3.pdf"   Some info regarding the (limitations of) the supported sql

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/899-helloid-provisioning-helloid-conn-prov-target-iprotect)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/

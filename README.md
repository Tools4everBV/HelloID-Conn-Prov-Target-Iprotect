## HelloID-Conn-Prov-Target-Iprotect

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

<br />

# Prerequisites

An Iprotect account ("systeemgebruiker") must be created with sufficient rights to query and update the employees and accesskeys
Make sure that the box "synchronisatie beheerder" is checked in the "detail systeemgebruiker", and that the account has sufficient rights to query and update the iprotect database

To verify this: login into the web GUI  with a browser of iprotect with this account and check 
1.  The ability to successfully query the accesskey, employee and user tables with this account
2.  The ability to use the import/export functionality manually with this account. 


# Configuration settings

- USER Webservice URL:	"https://<ip>:<port>/Webcontrols/automated/import"  URL used for updating users and accesskey
- XMLSQL Webservice URL	"https://<ip>:<port>/Webcontrols/"  base URL used for querying, en updating accesskey memberships  
- User name	
- Password	


# Available api documentation (included in this repo for info)

The following api info is included:
1. "automated import xmlsql.doc" Description of the import function for employees, as is used by create.ps1, update.ps1 and delete.ps1
2. "iProtect API v2.10.doc   Description of the xmlsql api, used for generic sql queries and updates
3. "Jdbc handleiding v0.3.pdf"   Some info regarding the (limitiations of) the supported sql


# Description of the available ps1 scripts

The Create, update and delete scripts use the simple import api, in which you just create a flat record of the employee data to create/update

- Create.ps1  
  Creates (imports) a new employee(and user)  optionally with an associated AccesskeyRCN 
  Expects the salaryNR as the ExternalID of the person, and the familyname of the person as required parameters, and the GivenName as optional.

  Note that what is often called by the enduser the "id" of the accesskey, actually is the AccesskeyRCN, and not the AccesskeyId, the AccesskeyId is rather the internal id used by the Iprotect database. 


- Update.ps1  
  Updates (imports) an existing employee 
  The default implementation only updates the most basic properties, modify to add more updated fields 

- Delete.ps1  
  Deletes (via import) an existing employee. Note that this does actually delete the Iprotect employee record, If you only want to change a status to denote the deletion use a modified update.ps1 instead for the delete actions in HelloId.

 All other scripts use the xmlsql interface to directly query and or update the database of iprotect with sql queries and/ or updates.
 For each single query/or update there are 4 required calls to be made, which may at first sight make the script look more complex than it actually is.

 1. A call is made to Webcontrols/XMLSQL (without credentials) by means of a Invoke-WebRequest to retreive a new websession object that contains a cookie.      
 2. A call is made to Webcontrols/j_security_check  to authenticate the user (using the websession object and cookie)
 3. A call is made to Webcontrols/XMLSQL (without explicit credentials) to execute the query (using the same websession object and cookie)
 4. A call is made to Webcontrols/XMLSQL to logout
 
   >Note that the actual identical sql query is posted in both step 1 and step 3, following the api doc.

- Disable.ps1  
  The default implementation:
  1. queries the iprotect database for all associated Accesskeys of the employee,
  2. loops through all the found associated accesskeys and
    1. sets the "valid" attribute of each key to 0.

  There is no enable.ps1 script but you can create that simply by copying the Disable.ps1 and changing the line  "$Enable= $false" to "$Enable= $true" in the top section.

- Entitlements.ps1  
  queries Iprotect for all keygroups.

- Grant.ps1  
  The default implementation:
  1. Queries the iprotect database for all associated Accesskeys of the employee
  2. Loops through all the found associated accesskeys and
    1. Makes each accesskey member of the specified entitlement (Keygroup):  
      "INSERT INTO keykeygroup (accesskeyid, keygroupid) VALUES ($accesskeyId,$keygroupId)

- Revoke.ps1  
  The default implementation:  
  1. Queries the iprotect database for all associated Accesskeys of the employee
  2. Loops through all the found associated accesskeys
      1. retrieves the keykeyid of the membership to revoke
          1. Queries the key memberships (keykeygroup) of this specific accesskey
          2. Filters on keygroupid (the entitlement) that should be revoked,
          3. Gets the associated keykeyid of memberships entry
      2. Issues an update query for deletion of the specific membership key.

  
  >Note, the revoke is complicated by restrictions on the allowed SQL query command for SELECT and UPDATE. 
  A WHERE clause is only allowed if there is an index on the specific combination of fields in the WHERE. 
  Because there is no combined index in keykeygroup on both  "accesskeyid" "keygroupid" they cannot be combined in the delete.
  Therefore we need to first collect the KeyKeyID

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/         

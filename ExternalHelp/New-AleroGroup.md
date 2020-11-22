---
external help file: cybrAlero-help.xml
Module Name: cybrAlero
online version:
schema: 2.0.0
---

# New-AleroGroup

## SYNOPSIS
This function create a new group in Alero.

## SYNTAX

```
New-AleroGroup [-Authn] <SecureString> [-Name] <String> [[-Description] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function create a new group in Alero.

## EXAMPLES

### Example 1
```powershell
PS C:\> New-AleroGroup -Authn $auth -Name Alero-PROD-EU
```

A new group called 'Alero-PROD-EU' is created in the Alero portal.

## PARAMETERS

### -Authn
Token to authenticate to Alero.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Description
The description of the AleroLDAP group.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name
The name of the AleroLDAP group that will be added as a member to CyberArk Safes.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Security.SecureString

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
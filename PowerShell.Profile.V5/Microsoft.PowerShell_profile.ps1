Write-Host -F DarkGray 'Loading profile'

#region -- Cred stuff (duplicate code)
# Src: https://gist.githubusercontent.com/ctigeek/2a56648b923d198a6e60/raw/99ea0ff903dc7240ca855921e7d0ceaf78caf721/PowershellAes.ps1
# 
# Alternative for random number generation (RNG) / key generation:
#

Function Generate-CryptoRandomBytes
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter(ParameterSetName='LengthBytes', Mandatory=$True)]
        [ValidateRange(0, 100000000)]
        [Int] $LengthBytes,
        
        [Parameter(ParameterSetName='LengthBits', Mandatory=$True)]
        [ValidateScript({
            if ($_ % 8 -eq 0)
            {
                $True
            }
            else
            {
                Throw 'LengthBits must be dividable by 8'
            }
        })]
        [ValidateRange(0, 800000000)]
        [Int] $LengthBits,
        
        [Switch] $AsBase64
    )
    
    if ($PSCmdlet.ParameterSetName -eq 'LengthBits')
    {
        $LengthBytes = $LengthBits / 8
    }
    
    $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $Buffer = New-Object Byte[] $LengthBytes
    $RNG.GetBytes($Buffer)
    
    if ($AsBase64)
    {
        [Convert]::ToBase64String($Buffer)
    }
    else
    {
        $Buffer
    }
}

#CHANGED
Function Create-AESManagedObject
{
    <#
        Src: Src: https://stackoverflow.com/questions/2503433/how-to-create-encryption-key-for-encryption-algorithms
    #>
    
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Object] $Key,
        [Object] $InitializationVector,
        [Int] $BlockSizeBits = 128,
        [Int] $KeySizeBits = 256
    )
    
    $AESManaged = New-Object System.Security.Cryptography.AesManaged
    $AESManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AESManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $AESManaged.BlockSize = $BlockSizeBits
    $AESManaged.KeySize = $KeySizeBits
    
    if ($Null -ne $InitializationVector)
    {
        if ($InitializationVector -is [String])
        {
            $InitializationVector = [System.Convert]::FromBase64String($InitializationVector)
        }
        $AESManaged.IV = $InitializationVector
    }
    
    if ($Null -ne $Key)
    {
        if ($Key -is [String])
        {
            $Key = [System.Convert]::FromBase64String($Key)
        }
        $AESManaged.Key = $Key
    }
    
    $AESManaged
}

Function Generate-AESKey
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Int] $KeySizeBits = 256
    )
    
    $AESManaged = Create-AESManagedObject -KeySizeBits $KeySizeBits
    $AESManaged.GenerateKey()
    [System.Convert]::ToBase64String($AESManaged.Key)
}

#CHANGED
Function Encrypt-AES
{
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [AllowEmptyString()] [String] $PlainTextString,
        [Object] $Key,
        [Object] $InitializationVector,
        [Switch] $NoIVInResult,
        [AllowEmptyString()] [String] $VerifyString = 'PSAES'
    )
    
    Begin
    {
        $CreateAESManagedObjectSplat = @{}
        'Key', 'InitializationVector' | ForEach-Object {
            if ($PSBoundParameters.ContainsKey($_))
            {
                $CreateAESManagedObjectSplat[$_] = $PSBoundParameters[$_]
            }
        }
    }
    
    Process
    {
        $PlainTextBytes = [Text.Encoding]::UTF8.GetBytes($VerifyString + $PlainTextString)
        
        $AESManaged = Create-AesManagedObject @CreateAESManagedObjectSplat
        try
        {
            $Encryptor = $AESManaged.CreateEncryptor()
            $EncryptedBytes = $Encryptor.TransformFinalBlock($PlainTextBytes, 0, $PlainTextBytes.Length)
            if (! $NoIVInResult)
            {
                $EncryptedBytes = $AESManaged.IV + $EncryptedBytes
            }
        }
        finally
        {
            $AESManaged.Dispose()
        }
        
        [System.Convert]::ToBase64String($EncryptedBytes)
    }
}

#CHANGED
Function Decrypt-AES
{
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [String] $EncryptedString,
        [Object] $Key,
        [Object] $InitializationVector,
        [Int] $BlockSizeBits = 128,
        [AllowEmptyString()] [String] $VerifyString = 'PSAES'
    )
    
    Begin
    {
        $CreateAESManagedObjectSplat = @{}
        'Key', 'BlockSizeBits' | ForEach-Object {
            if ($PSBoundParameters.ContainsKey($_))
            {
                $CreateAESManagedObjectSplat[$_] = $PSBoundParameters[$_]
            }
        }
        
        if ($Null -ne $InitializationVector)
        {
            if ($InitializationVector -is [String])
            {
                $InitializationVector = [System.Convert]::FromBase64String($InitializationVector)
            }
        }
    }
    
    Process
    {
        $EncryptedBytesWithIV = [System.Convert]::FromBase64String($EncryptedString)
        
        if ($Null -ne $InitializationVector)
        {
            $CurrentInitializationVector = $InitializationVector
            $InitializationVectorLengthInEncryptedBytes = 0
        }
        else
        {
            $InitializationVectorLengthInEncryptedBytes = $BlockSizeBits / 8
            $CurrentInitializationVector = $EncryptedBytesWithIV[0 .. ($InitializationVectorLengthInEncryptedBytes - 1)]
        }
        
        $AESManaged = Create-AESManagedObject -InitializationVector $CurrentInitializationVector @CreateAESManagedObjectSplat
        try
        {
            $Decryptor = $AESManaged.CreateDecryptor();
            $PlainTextBytes = $Decryptor.TransformFinalBlock(
                $EncryptedBytesWithIV,
                $InitializationVectorLengthInEncryptedBytes,
                $EncryptedBytesWithIV.Length - $InitializationVectorLengthInEncryptedBytes
            )
        }
        finally
        {
            $AESManaged.Dispose()
        }
        
        $PlainTextString = [Text.Encoding]::UTF8.GetString($PlainTextBytes)
        if ($VerifyString.Length -gt 0)
        {
            if (($PlainTextString.Length -ge $VerifyString.Length) -and
                ($PlainTextString.Substring(0, $VerifyString.Length).Equals($VerifyString)))
            {
                $PlainTextString = $PlainTextString.Substring($VerifyString.Length)
            }
            else
            {
                Throw 'AES Decryption failed. Wrong key?'
            }
        }
        
        $PlainTextString
    }
}

#
# Example
#
#   $Key = Generate-AESKey
#   $Key
#   $EncryptedStrings = 11, 22, 33, 'All righty' | Encrypt-AES -Key $Key
#   $EncryptedStrings
#   $EncryptedStrings | Decrypt-AES -Key $Key
#


# $Key = Generate-CryptoRandomBytes -LengthBits 256 -AsBase64


Function Verify-KeePassHTTPResponse
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, Position=0)] [Object] $Response,
        [Parameter(Mandatory=$True)] [String] $Key
    )
    
    Process
    {
        if ($Response -is [String])
        {
            $Response = ConvertFrom-Json $Response
        }
        
        $Success = $False
        try
        {
            $Success = $Response.Nonce.Equals(
                (Decrypt-AES $Response.Verifier -Key $Key -VerifyString '' -InitializationVector $Response.Nonce)
            )
        }
        catch {}
        
        $Success
    }
}

Function Test-KeePassHTTPAssociateUnencrypted
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [String] $Hostname = 'localhost',
        [Int] $Port = 19455
    )
    
    $RequestBody = @{
        RequestType = 'test-associate'
    } | ConvertTo-Json
    
    $HTTPResponse = Invoke-WebRequest -Uri "http://${Hostname}:$Port" -Method Post -Body $RequestBody
    $HTTPResponse.Content | ConvertFrom-Json
}

Function Test-KeePassHTTPAssociate
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter(Mandatory=$True)] [String] $Key,
        [Parameter(Mandatory=$True)] [String] $ID,
        [String] $Hostname = 'localhost',
        [Int] $Port = 19455
    )
    
    $Nonce = Generate-CryptoRandomBytes -LengthBits 128 -AsBase64
    
    $RequestBody = @{
        RequestType = 'test-associate'
        # TriggerUnlock = $False
        Id = $ID
        Nonce = $Nonce
        Verifier = Encrypt-AES $Nonce -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
    } | ConvertTo-Json
    
    $HTTPResponse = Invoke-WebRequest -Uri "http://${Hostname}:$Port" -Method Post -Body $RequestBody
    $Response = $HTTPResponse.Content | ConvertFrom-Json
    
    $Success = $False
    
    if ($Response.Success)
    {
        if (! (Verify-KeePassHTTPResponse $Response -Key $Key))
        {
            Throw "Verification failed for response: $($HTTPResponse.Content)"
        }
        
        $Success = $True
    }
    
    $Success
}

Function Associate-KeePassHTTP
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter(Mandatory=$True)] [String] $Key,
        [String] $Hostname = 'localhost',
        [Int] $Port = 19455
    )
    
    $Nonce = Generate-CryptoRandomBytes -LengthBits 128 -AsBase64
    
    $RequestBody = @{
        RequestType = 'associate'
        Key = $Key
        Nonce = $Nonce
        Verifier = Encrypt-AES $Nonce -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
    } | ConvertTo-Json
    
    $HTTPResponse = Invoke-WebRequest -Uri "http://${Hostname}:$Port" -Method Post -Body $RequestBody
    $Response = $HTTPResponse.Content | ConvertFrom-Json
    
    if ($Response.Success)
    {
        if (! (Verify-KeePassHTTPResponse $Response -Key $Key))
        {
            Throw "Verification failed for response: $($HTTPResponse.Content)"
        }
        
        $Response | Select Id, Hash
    }
    else
    {
        Throw "Could not associate with KeePass. Response: $($HTTPResponse.Content)"
    }
}

Function Get-KeePassHTTPEntry
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter(Mandatory=$True)] [String] $Key,
        [Parameter(Mandatory=$True)] [String] $ID,
        [Parameter(Mandatory=$True)] [AllowEmptyString()] [String] $Filter,
        [Switch] $AsPSCredential,
        [String] $Hostname = 'localhost',
        [Int] $Port = 19455
    )
    
    $Nonce = Generate-CryptoRandomBytes -LengthBits 128 -AsBase64
    
    $RequestBody = @{
        RequestType = 'get-logins'
        ID = $ID
        Nonce = $Nonce
        Verifier = Encrypt-AES $Nonce -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
        URL = Encrypt-AES $Filter -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
    } | ConvertTo-Json
    
    $HTTPResponse = Invoke-WebRequest -Uri "http://${Hostname}:$Port" -Method Post -Body $RequestBody
    $Response = $HTTPResponse.Content | ConvertFrom-Json
    
    if ($Response.Success)
    {
        if (! (Verify-KeePassHTTPResponse $Response -Key $Key))
        {
            Throw "Verification failed for response: $($HTTPResponse.Content)"
        }
        
        foreach ($Entry in $Response.Entries)
        {
            $PasswordPlainText = Decrypt-AES $Entry.Password -Key $Key -VerifyString '' -InitializationVector $Response.Nonce
            if ($PasswordPlainText)
            {
                $Password = ConvertTo-SecureString -String $PasswordPlainText -AsPlainText -Force
            }
            else
            {
                $Password = New-Object Security.SecureString
            }
            
            if ($AsPSCredential)
            {
                $Username = Decrypt-AES $Entry.Login -Key $Key -VerifyString '' -InitializationVector $Response.Nonce
                if (! $Username)
                {
                    $Username = ' '
                }
                New-Object PSCredential $Username, $Password
            }
            else
            {
                [PSCustomObject] @{
                    Name = Decrypt-AES $Entry.Name -Key $Key -VerifyString '' -InitializationVector $Response.Nonce
                    Username = Decrypt-AES $Entry.Login -Key $Key -VerifyString '' -InitializationVector $Response.Nonce
                    Password = $Password
                    UUID = Decrypt-AES $Entry.Uuid -Key $Key -VerifyString '' -InitializationVector $Response.Nonce
                }
            }
        }
    }
    else
    {
        Throw "Could not get KeePass entries. Response: $($HTTPResponse.Content)"
    }
}

Function Get-KeePassHTTPEntryCount
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter(Mandatory=$True)] [String] $Key,
        [Parameter(Mandatory=$True)] [String] $ID,
        [Parameter(Mandatory=$True)] [AllowEmptyString()] [String] $Filter,
        [Switch] $AsPSCredential,
        [String] $Hostname = 'localhost',
        [Int] $Port = 19455
    )
    
    $Nonce = Generate-CryptoRandomBytes -LengthBits 128 -AsBase64
    
    $RequestBody = @{
        RequestType = 'get-logins-count'
        ID = $ID
        Nonce = $Nonce
        Verifier = Encrypt-AES $Nonce -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
        URL = Encrypt-AES $Filter -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
    } | ConvertTo-Json
    
    $HTTPResponse = Invoke-WebRequest -Uri "http://${Hostname}:$Port" -Method Post -Body $RequestBody
    $Response = $HTTPResponse.Content | ConvertFrom-Json
    
    if ($Response.Success)
    {
        if (! (Verify-KeePassHTTPResponse $Response -Key $Key))
        {
            Throw "Verification failed for response: $($HTTPResponse.Content)"
        }
        
        $Response.Count
    }
    else
    {
        Throw "Could not get KeePass entries. Response: $($HTTPResponse.Content)"
    }
}

Function New-KeePassHTTPEntry
{
    [CmdletBinding(PositionalBinding=$False)]
    Param(
        [Parameter(Mandatory=$True)] [String] $Key,
        [Parameter(Mandatory=$True)] [String] $ID,
        [Parameter(Mandatory=$True)] [String] $Username,
        [Parameter(Mandatory=$True)] [String] $Password,
        [Parameter(Mandatory=$True)] [String] $URL,
        [String] $Hostname = 'localhost',
        [Int] $Port = 19455
    )
    
    $Nonce = Generate-CryptoRandomBytes -LengthBits 128 -AsBase64
    
    $RequestBody = @{
        RequestType = 'set-login'
        ID = $ID
        Nonce = $Nonce
        Verifier = Encrypt-AES $Nonce -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
        Login = Encrypt-AES $Username -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
        Password = Encrypt-AES $Password -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
        URL = Encrypt-AES $URL -Key $Key -InitializationVector $Nonce -NoIVInResult -VerifyString ''
    } | ConvertTo-Json
    
    $HTTPResponse = Invoke-WebRequest -Uri "http://${Hostname}:$Port" -Method Post -Body $RequestBody
    $Response = $HTTPResponse.Content | ConvertFrom-Json
    
    if ($Response.Success)
    {
        if (! (Verify-KeePassHTTPResponse $Response -Key $Key))
        {
            Throw "Verification failed for response: $($HTTPResponse.Content)"
        }
    }
    else
    {
        Throw "Could not create KeePass entry. Response: $($HTTPResponse.Content)"
    }
}







Function Convert-SecureStringToPlainText
{
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)] [System.Security.SecureString] $SecureString
    )
    
    Process
    {
        $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        try
        {
            $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
        }
        catch
        {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
        }
        
        $PlainTextPassword
    }
}

Function Convert-PlainTextStringToSecureString
{
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory=$True)] [AllowEmptyString()] [String] $PlainTextString
    )
    
    Process
    {
        if ($PlainTextString.Length -eq 0)
        {
            New-Object System.Security.SecureString
        }
        else
        {
            ConvertTo-SecureString -String $PlainTextString -AsPlainText -Force
        }
    }
}

#CHANGED
Function Get-PasswordStringFromSecureString
{
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)] [System.Security.SecureString] $SecureString,
        
        [Parameter(ParameterSetName='EncryptWithUserKey', Mandatory=$True)] [ValidateSet($True)] [Switch] $EncryptWithUserKey,
        
        [Parameter(ParameterSetName='EncryptWithMachineKey', Mandatory=$True)] [ValidateSet($True)] [Switch] $EncryptWithMachineKey,
        
        [Parameter(ParameterSetName='EncryptWithCertificate', Mandatory=$True)] [ValidateSet($True)] [Switch] $EncryptWithCertificate,
        [Parameter(ParameterSetName='EncryptWithCertificate', Mandatory=$True)] [String] $CertificatePath,
        
        [Parameter(ParameterSetName='PlainText', Mandatory=$True)] [ValidateSet($True)] [Switch] $PlainText
    )
    
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    
    Process
    {
        $InfoObjectProperties = @{}
        
        switch ($PSCmdlet.ParameterSetName)
        {
            'EncryptWithUserKey'
            {
                $InfoObjectProperties['Password'] = $SecureString | Convert-SecureStringToPlainText | Encrypt-DPAPI -DataProtectionScope CurrentUser
                $InfoObjectProperties['CryptoProvider'] = 'DPAPIUser'
            }
            'EncryptWithMachineKey'
            {
                $InfoObjectProperties['Password'] = $SecureString | Convert-SecureStringToPlainText | Encrypt-DPAPI -DataProtectionScope LocalMachine
                $InfoObjectProperties['CryptoProvider'] = 'DPAPIMachine'
            }
            'EncryptWithCertificate'
            {
                if ((Get-Item $CertificatePath).PSDrive.Provider.Name -eq 'Certificate')
                {
                    $Certificate = Get-Item $CertificatePath
                }
                else
                {
                    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
                }
                
                $ByteArray = [System.Text.Encoding]::UTF8.GetBytes(($SecureString | Convert-SecureStringToPlainText))
                $EncryptedByteArray = $Certificate.PublicKey.Key.Encrypt($ByteArray, $True)
                
                $InfoObjectProperties['Password'] = [Convert]::ToBase64String($EncryptedByteArray)
                $InfoObjectProperties['CryptoProvider'] = 'Certificate'
                $InfoObjectProperties['CertificateThumbprint'] = $Certificate.Thumbprint
            }
            'PlainText'
            {
                $InfoObjectProperties['Password'] = $SecureString | Convert-SecureStringToPlainText
                $InfoObjectProperties['CryptoProvider'] = 'ClearText'
            }
            default
            {
                Throw "Unexpected parameter set name: $($PSCmdlet.ParameterSetName)"
            }
        }
        
        $JSON = [PSCustomObject] $InfoObjectProperties | ConvertTo-Json -Compress
        
        $ByteArray = [Text.Encoding]::UTF8.GetBytes($JSON)
        
        #region -- Compress
        $MS = New-Object IO.MemoryStream
        $DS = New-Object IO.Compression.DeflateStream @($MS, [IO.Compression.CompressionLevel]::Optimal)
        try
        {
            $DS.Write($ByteArray, 0, $ByteArray.Length)
        }
        finally
        {
            $DS.Close()
        }
        $ByteArray = $MS.ToArray()
        #endregion
        
        [Convert]::ToBase64String($ByteArray)
    }
}

Function Get-SecureStringFromPasswordString
{
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)] [String] $PasswordString
    )
    
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    
    Process
    {
        $ByteArray = [Convert]::FromBase64String($PasswordString)
        
        #region -- Decompress
        $IMS = New-Object IO.MemoryStream (,@($ByteArray))
        $OMS = New-Object IO.MemoryStream
        $DS = New-Object IO.Compression.DeflateStream @($IMS, [IO.Compression.CompressionMode]::Decompress)
        try
        {
            $DS.CopyTo($OMS)
        }
        finally
        {
            $DS.Close()
        }
        $ByteArray = $OMS.ToArray()
        #endregion
        
        $JSON = [Text.Encoding]::UTF8.GetString($ByteArray)
        
        $InfoObject = $JSON | ConvertFrom-Json
        
        switch ($InfoObject.CryptoProvider)
        {
            'DPAPIUser'
            {
                $SecureString = $InfoObject.Password | Decrypt-DPAPI -DataProtectionScope CurrentUser | Convert-PlainTextStringToSecureString
            }
            'DPAPIMachine'
            {
                $SecureString = $InfoObject.Password | Decrypt-DPAPI -DataProtectionScope LocalMachine | Convert-PlainTextStringToSecureString
            }
            'Certificate'
            {
                $CertificateThumbprint = $InfoObject.CertificateThumbprint
                $Certificate = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                if ($Null -eq $Certificate)
                {
                    $Certificate = Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                }
                
                if ($Null -eq $Certificate)
                {
                    Throw "Certificate not found with thumbprint: $CertificateThumbprint"
                }
                
                if ($Null -eq $Certificate.PrivateKey)
                {
                    Throw 'Certificate found but its private key cannot be accessed'
                }
                
                $EncryptedByteArray = [Convert]::FromBase64String($InfoObject.Password)
                $ClearText = [System.Text.Encoding]::UTF8.GetString($Certificate.PrivateKey.Decrypt($EncryptedByteArray, $True))
                
                $SecureString = $ClearText | Convert-PlainTextStringToSecureString
            }
            'ClearText'
            {
                $SecureString = $InfoObject.Password | Convert-PlainTextStringToSecureString
            }
            default
            {
                Throw "Unexpected crypto provider: $($InfoObject.CryptoProvider)"
            }
        }
        
        $SecureString
    }
}

Function New-Credential
{
    [CmdletBinding(DefaultParameterSetName='PasswordSecure')]
    Param(
        [Parameter(Position=0,Mandatory=$True)]
        [String] $Username,
        
        [Parameter(Position=1,ParameterSetName="PasswordSecure",Mandatory=$True)]
        [System.Security.SecureString] $Password,
        
        [Parameter(Position=1,ParameterSetName="PasswordPlaintext",Mandatory=$True)]
        [AllowEmptyString()] [String] $PasswordPlainText
    )
    
    if ($PSCmdlet.ParameterSetName -eq 'PasswordPlainText')
    {
        $Password = Convert-PlainTextStringToSecureString $PasswordPlainText
    }
    
    New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password
}

#CHANGED
Function Encrypt-Asymmetric
{
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)] [AllowNull()] [Object] $InputObject,
        [Switch] $DecodeBase64,
        [Parameter(Mandatory=$True)] [String] $CertificateFilePath
    )
    
    Begin
    {
        if ((Get-Item $CertificateFilePath).PSDrive.Provider.Name -eq 'Certificate')
        {
            $Certificate = Get-Item $CertificateFilePath
        }
        else
        {
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificateFilePath)
        }
    }
    
    Process
    {
        $InputObjectBytes = [Byte[]] @()
        if ($DecodeBase64)
        {
            $InputObjectBytes = [Convert]::FromBase64String($InputObject)
        }
        elseif ($Null -ne $InputObject)
        {
            if ($InputObject -is [Byte[]])
            {
                $InputObjectBytes = $InputObject
            }
            else
            {
                $InputObjectBytes = [Text.Encoding]::UTF8.GetBytes($InputObject.ToString())
            }
        }
        
        $EncryptedByteArray = $Certificate.PublicKey.Key.Encrypt($InputObjectBytes, $True)
        $Base64String = [Convert]::ToBase64String($EncryptedByteArray)
        
        $Base64String
    }
}

#CHANGED
Function Decrypt-Asymmetric
{
    [CmdletBinding(DefaultParameterSetName='OutString')]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [Object] $InputObject,
        
        [Parameter(ParameterSetName='OutString')]
        [ValidateSet($True)]
        [Switch] $OutString,
        
        [Parameter(ParameterSetName='OutBase64')]
        [ValidateSet($True)]
        [Switch] $OutBase64,
        
        [Parameter(ParameterSetName='OutBytes')]
        [ValidateSet($True)]
        [Switch] $OutBytes,
        
        [Parameter(Mandatory=$True)] [String] $CertificateFilePath
    )
    
    Begin
    {
        $Certificate = Get-Item $CertificateFilePath
    }
    
    Process
    {
        if ($InputObject -is [Byte[]])
        {
            $InputObjectBytes = $InputObject
        }
        elseif ($InputObject -is [String])
        {
            $InputObjectBytes = [Convert]::FromBase64String($InputObject)
        }
        else
        {
            Throw "Input must be either a byte array or a base64 string - got: $($InputObject.GetType().FullName)"
        }
        
        $OutputBytes = $Certificate.PrivateKey.Decrypt($InputObjectBytes, $True)
        
        switch ($PSCmdlet.ParameterSetName)
        {
            OutString { [Text.Encoding]::UTF8.GetString($OutputBytes); break }
            OutBase64 { [Convert]::ToBase64String($OutputBytes); break }
            OutBytes { , $OutputBytes; break }
            default { Throw 'Unexpected ParameterSetName: $($PSCmdlet.ParameterSetName)' }
        }
    }
}

#CHANGED
Function Encrypt-DPAPI
{
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [AllowNull()] [Object] $InputObject,
        [Switch] $DecodeBase64,
        [System.Security.Cryptography.DataProtectionScope] $DataProtectionScope = 'CurrentUser',
        [Byte[]] $Entropy = $Null
    )
    
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    
    Process
    {
        $InputObjectBytes = [Byte[]] @()
        if ($DecodeBase64)
        {
            $InputObjectBytes = [Convert]::FromBase64String($InputObject)
        }
        elseif ($Null -ne $InputObject)
        {
            if ($InputObject -is [Byte[]])
            {
                $InputObjectBytes = $InputObject
            }
            else
            {
                $InputObjectBytes = [Text.Encoding]::UTF8.GetBytes($InputObject.ToString())
            }
        }
        
        [Convert]::ToBase64String(
            [Security.Cryptography.ProtectedData]::Protect(
                $InputObjectBytes,
                $Entropy,
                $DataProtectionScope
            )
        )
    }
}

#CHANGED
Function Decrypt-DPAPI
{
    [CmdletBinding(DefaultParameterSetName='OutString')]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [Object] $InputObject,
        
        [Parameter(ParameterSetName='OutString')]
        [ValidateSet($True)]
        [Switch] $OutString,
        
        [Parameter(ParameterSetName='OutBase64')]
        [ValidateSet($True)]
        [Switch] $OutBase64,
        
        [Parameter(ParameterSetName='OutBytes')]
        [ValidateSet($True)]
        [Switch] $OutBytes,
        
        [System.Security.Cryptography.DataProtectionScope] $DataProtectionScope = 'CurrentUser',
        [Byte[]] $Entropy = $Null
    )
    
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    
    Process
    {
        if ($InputObject -is [Byte[]])
        {
            $InputObjectBytes = $InputObject
        }
        elseif ($InputObject -is [String])
        {
            $InputObjectBytes = [Convert]::FromBase64String($InputObject)
        }
        else
        {
            Throw "Input must be either a byte array or a base64 string - got: $($InputObject.GetType().FullName)"
        }
        
        $OutputBytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $InputObjectBytes,
            $Entropy,
            $DataProtectionScope
        )
        
        switch ($PSCmdlet.ParameterSetName)
        {
            OutString { [Text.Encoding]::UTF8.GetString($OutputBytes); break }
            OutBase64 { [Convert]::ToBase64String($OutputBytes); break }
            OutBytes { , $OutputBytes; break }
            default { Throw 'Unexpected ParameterSetName: $($PSCmdlet.ParameterSetName)' }
        }
    }
}

#CHANGED
Function Convert-CredentialToString
{
    [CmdletBinding(DefaultParameterSetName='EncryptWithUserKey')]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [PSCredential] $Credential,
        
        [Parameter(ParameterSetName='EncryptWithUserKey')] [ValidateSet($True)] [Switch] $EncryptWithUserKey,
        
        [Parameter(ParameterSetName='EncryptWithMachineKey')] [ValidateSet($True)] [Switch] $EncryptWithMachineKey,
        
        [Parameter(ParameterSetName='EncryptWithCertificate')] [ValidateSet($True)] [Switch] $EncryptWithCertificate,
        [Parameter(Mandatory=$True, ParameterSetName='EncryptWithCertificate')] [String] $CertificatePath,
        
        [Parameter(ParameterSetName='PlainText')] [ValidateSet($True)] [Switch] $PlainText
    )
    
    Process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'EncryptWithUserKey'
            {
                $PasswordString = $Credential.Password | Convert-SecureStringToPlainText | ConvertTo-SecretString -EncryptWithUserKey
            }
            'EncryptWithMachineKey'
            {
                $PasswordString = $Credential.Password | Convert-SecureStringToPlainText | ConvertTo-SecretString -EncryptWithMachineKey
            }
            'EncryptWithCertificate'
            {
                $PasswordString = $Credential.Password | Convert-SecureStringToPlainText | ConvertTo-SecretString -EncryptWithCertificate -CertificatePath $CertificatePath
            }
            'PlainText'
            {
                $PasswordString = $Credential.Password | Convert-SecureStringToPlainText | ConvertTo-SecretString -PlainText
            }
            default
            {
                Throw "Unexpected parameter set name: $($PSCmdlet.ParameterSetName)"
            }
        }
        
        $JSON = [PSCustomObject] @{ Username = $Credential.Username; PasswordString = $PasswordString } | ConvertTo-Json -Compress
        [Convert]::ToBase64String( [Text.Encoding]::UTF8.GetBytes($JSON) )
    }
}

#CHANGED
Function Convert-CredentialFromString
{
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)] [String] $CredentialString
    )
    
    Process
    {
        $JSON = [Text.Encoding]::UTF8.GetString( [Convert]::FromBase64String($CredentialString) )
        $CredentialInfo = $JSON | ConvertFrom-Json
        
        $PasswordSecureString = $CredentialInfo.PasswordString | ConvertFrom-SecretString | Convert-PlainTextStringToSecureString
        New-Credential -Username $CredentialInfo.Username -Password $PasswordSecureString
    }
}



################################################################################################
################################################################################################
################################################################################################

#CHANGED
Function ConvertTo-SecretString
{
    [CmdletBinding(DefaultParameterSetName='EncryptWithUserKey')]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [AllowNull()] [Object] $InputObject,
        [Switch] $DecodeBase64,
        
        [Parameter(ParameterSetName='EncryptWithUserKey')] [ValidateSet($True)] [Switch] $EncryptWithUserKey,
        
        [Parameter(ParameterSetName='EncryptWithMachineKey')] [ValidateSet($True)] [Switch] $EncryptWithMachineKey,
        
        [Parameter(ParameterSetName='EncryptWithCertificate')] [ValidateSet($True)] [Switch] $EncryptWithCertificate,
        [Parameter(ParameterSetName='EncryptWithCertificate', Mandatory=$True)] [String] $CertificatePath,
        
        [Parameter(ParameterSetName='PlainText')] [ValidateSet($True)] [Switch] $PlainText
    )
    
    
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    
    Process
    {
        $InputObjectBytes = [Byte[]] @()
        if ($DecodeBase64)
        {
            $InputObjectBytes = [Convert]::FromBase64String($InputObject)
        }
        elseif ($Null -ne $InputObject)
        {
            if ($InputObject -is [Byte[]])
            {
                $InputObjectBytes = $InputObject
            }
            else
            {
                $InputObjectBytes = [Text.Encoding]::UTF8.GetBytes($InputObject.ToString())
            }
        }
        
        $InfoObjectProperties = @{}
        
        switch ($PSCmdlet.ParameterSetName)
        {
            'EncryptWithUserKey'
            {
                $InfoObjectProperties['Content'] = Encrypt-DPAPI -InputObject $InputObjectBytes -DataProtectionScope CurrentUser
                $InfoObjectProperties['CryptoProvider'] = 'DPAPIUser'
            }
            'EncryptWithMachineKey'
            {
                $InfoObjectProperties['Content'] = Encrypt-DPAPI -InputObject $InputObjectBytes -DataProtectionScope LocalMachine
                $InfoObjectProperties['CryptoProvider'] = 'DPAPIMachine'
            }
            'EncryptWithCertificate'
            {
                if ((Get-Item $CertificatePath).PSDrive.Provider.Name -eq 'Certificate')
                {
                    $Certificate = Get-Item $CertificatePath
                }
                else
                {
                    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
                }
                
                $EncryptedByteArray = $Certificate.PublicKey.Key.Encrypt($InputObjectBytes, $True)
                
                $InfoObjectProperties['Content'] = [Convert]::ToBase64String($EncryptedByteArray)
                $InfoObjectProperties['CryptoProvider'] = 'Certificate'
                $InfoObjectProperties['CertificateThumbprint'] = $Certificate.Thumbprint
            }
            'PlainText'
            {
                $InfoObjectProperties['Content'] = [Convert]::ToBase64String($InputObjectBytes)
                $InfoObjectProperties['CryptoProvider'] = 'ClearText'
            }
            default
            {
                Throw "Unexpected parameter set name: $($PSCmdlet.ParameterSetName)"
            }
        }
        
        $JSON = [PSCustomObject] $InfoObjectProperties | ConvertTo-Json -Compress
        
        $ByteArray = [Text.Encoding]::UTF8.GetBytes($JSON)
        
        #region -- Compress
        $MS = New-Object IO.MemoryStream
        $DS = New-Object IO.Compression.DeflateStream @($MS, [IO.Compression.CompressionLevel]::Optimal)
        try
        {
            $DS.Write($ByteArray, 0, $ByteArray.Length)
        }
        finally
        {
            $DS.Close()
        }
        $ByteArray = $MS.ToArray()
        #endregion
        
        [Convert]::ToBase64String($ByteArray)
    }
}

Function ConvertFrom-SecretString
{
    [CmdletBinding(DefaultParameterSetName='OutString')]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)] [Object] $InputObject,
        
        [Parameter(ParameterSetName='OutString')]
        [ValidateSet($True)]
        [Switch] $OutString,
        
        [Parameter(ParameterSetName='OutBase64')]
        [ValidateSet($True)]
        [Switch] $OutBase64,
        
        [Parameter(ParameterSetName='OutBytes')]
        [ValidateSet($True)]
        [Switch] $OutBytes
    )
    
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    
    Process
    {
        if ($InputObject -is [Byte[]])
        {
            $InputObjectBytes = $InputObject
        }
        elseif ($InputObject -is [String])
        {
            $InputObjectBytes = [Convert]::FromBase64String($InputObject)
        }
        else
        {
            Throw "Input must be either a byte array or a base64 string - got: $($InputObject.GetType().FullName)"
        }
        
        #region -- Decompress
        $IMS = New-Object IO.MemoryStream (,@($InputObjectBytes))
        $OMS = New-Object IO.MemoryStream
        $DS = New-Object IO.Compression.DeflateStream @($IMS, [IO.Compression.CompressionMode]::Decompress)
        try
        {
            $DS.CopyTo($OMS)
        }
        finally
        {
            $DS.Close()
        }
        $InputObjectBytes = $OMS.ToArray()
        #endregion
        
        $JSON = [Text.Encoding]::UTF8.GetString($InputObjectBytes)
        
        $InfoObject = $JSON | ConvertFrom-Json
        
        $OutParamsSplat = @{}
        foreach ($ParamName in ($PSBoundParameters.Keys | Where-Object { $_ -like 'Out*' }))
        {
            $OutParamsSplat[$ParamName] = $PSBoundParameters[$ParamName]
        }
        
        $Output = $Null
        
        switch ($InfoObject.CryptoProvider)
        {
            'DPAPIUser'
            {
                $Output = $InfoObject.Content | Decrypt-DPAPI -DataProtectionScope CurrentUser @OutParamsSplat
            }
            'DPAPIMachine'
            {
                $Output = $InfoObject.Content | Decrypt-DPAPI -DataProtectionScope LocalMachine @OutParamsSplat
            }
            'Certificate'
            {
                $CertificateThumbprint = $InfoObject.CertificateThumbprint
                $Certificate = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                if ($Null -eq $Certificate)
                {
                    $Certificate = Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                }
                
                if ($Null -eq $Certificate)
                {
                    Throw "Certificate not found with thumbprint: $CertificateThumbprint"
                }
                
                if ($Null -eq $Certificate.PrivateKey)
                {
                    Throw 'Certificate found but its private key cannot be accessed'
                }
                
                $EncryptedByteArray = [Convert]::FromBase64String($InfoObject.Content)
                $ClearText = [System.Text.Encoding]::UTF8.GetString($Certificate.PrivateKey.Decrypt($EncryptedByteArray, $True))
                
                switch ($PSCmdlet.ParameterSetName)
                {
                    OutString { $Output = $ClearText; break }
                    OutBase64 { $Output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ClearText)); break }
                    OutBytes { $Output = [Text.Encoding]::UTF8.GetBytes($ClearText); break }
                    default { Throw 'Unexpected ParameterSetName: $($PSCmdlet.ParameterSetName)' }
                }
            }
            'ClearText'
            {
                switch ($PSCmdlet.ParameterSetName)
                {
                    OutString { $Output = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($InfoObject.Content)); break }
                    OutBase64 { $Output = $InfoObject.Content; break }
                    OutBytes { $Output = [Convert]::FromBase64String($InfoObject.Content); break }
                    default { Throw 'Unexpected ParameterSetName: $($PSCmdlet.ParameterSetName)' }
                }
            }
            default
            {
                Throw "Unexpected crypto provider: $($InfoObject.CryptoProvider)"
            }
        }
        
        switch ($PSCmdlet.ParameterSetName)
        {
            OutString { $Output; break }
            OutBase64 { $Output; break }
            OutBytes { , $Output; break }
            default { Throw 'Unexpected ParameterSetName: $($PSCmdlet.ParameterSetName)' }
        }
    }
}
#endregion

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
[Console]::BufferHeight = 9999

#region -- Fast YAML and Merge-Object
Add-Type -Path "$PSScriptRoot\YamlDotNet.dll"

Function ConvertFrom-YAMLQuickly
{
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)] $YAMLString
    )
    
    Process
    {
        $StringReader = New-Object System.IO.StringReader $YAMLString
        $YAMLStream = New-Object YamlDotNet.RepresentationModel.YamlStream
        $YAMLStream.Load($StringReader)
        # [System.IO.TextReader]
        $RootNode = $YAMLStream.Documents[0].RootNode
        
        $ResultList = New-Object System.Collections.ArrayList
        $ResultList.Add($Null) > $Null
        
        $Queue = New-Object System.Collections.Queue
        $Queue.Enqueue(@{ Container = $ResultList; Location = 0; Item = $RootNode })
        
        while ($Queue.Count -gt 0)
        {
            $CurrentItemInfo = $Queue.Dequeue()
            $CurrentItem = $CurrentItemInfo['Item']
            
            if ($Null -eq $CurrentItem)
            {
                Throw "<null> encountered - ItemInfo: $($CurrentItemInfo | Out-String)"
            }
            
            $TypeOfNode = $CurrentItem.GetType().Name
            switch ($TypeOfNode)
            {
                YamlMappingNode
                {
                    $HashTableContainer = [Ordered] @{}
                    foreach ($KeyNode in $CurrentItem.Children.Keys)
                    {
                        $Item = $CurrentItem.Children[$KeyNode]
                        $Key = $KeyNode.Value
                        # $HashTableContainer[$Key] = '<placeholder>';
                        $Queue.Enqueue(@{ Container = $HashTableContainer; Location = $Key; Item = $Item })
                    }
                    $CurrentValue = $HashTableContainer
                }
                
                YamlSequenceNode
                {
                    $ArrayListContainer = New-Object System.Collections.ArrayList
                    foreach ($ChildItem in $CurrentItem.Children)
                    {
                        $Index = $ArrayListContainer.Add($Null) # Add a place holder in the ArrayList Container
                        $Queue.Enqueue(@{ Container = $ArrayListContainer; Location = $Index; Item = $ChildItem })
                    }
                    $CurrentValue = $ArrayListContainer
                }
                
                YamlScalarNode
                {
                    $CurrentValue = switch ($CurrentItem.Tag)
                    {
                        
                        'tag:yaml.org,2002:bool'      { [Bool]::Parse($CurrentItem.Value); break }
                        'tag:yaml.org,2002:float'     { [Double] $CurrentItem.Value; break }
                        'tag:yaml.org,2002:int'       { [Int] $CurrentItem.Value; break }
                        'tag:yaml.org,2002:null'      { $Null; break }
                        'tag:yaml.org,2002:timestamp' { [DateTime] $CurrentItem.Value; break }
                        'tag:yaml.org,2002:binary'    { [System.Convert]::FromBase64String($CurrentItem.Value); break }
                        'tag:yaml.org,2002:seq'       { if ($CurrentItem.Value) { , ([Collections.ArrayList] @($CurrentItem.Value)) } else { , ([Collections.ArrayList] @()) }; break }
                        default                       { $CurrentItem.Value } # Value is a string
                    }
                }
                
                default
                {
                    Throw "Unhandled type: $TypeOfNode"
                }
            }
            
            # Put actual value to the correct location in within the object structure
            $Location = $CurrentItemInfo['Location']
            $CurrentItemInfo['Container'][$Location] = $CurrentValue
        }
        
        $ResultList # PowerShell will return the content into pipeline, not the ArrayList object
    }
}

Function Merge-Object
{
    <#
        .SYNOPSIS
            Merges two objects. Originally it supported only structures consisting of modifyable ILists and IDictionaries.
            
            But now arrays are supported as long as: Object1 -isnot [Array]. They will be converted to ArrayLists.
            
            Also PSObjects can be treated like dictionaries using the -TreatPSObjectsLikeDictionaries parameter.
            
            Object2 will be merged into Object1; therefore Object1 will be modified.
    #>
    
    Param(
        $Object1,
        $Object2,
        [ValidateSet('Object1Wins', 'Object2Wins')] [String] $OverrideStrategy = 'Object2Wins',
        [ValidateSet('Object1First', 'Object2First')] [String] $CollectionOrder = 'Object1First',
        [Switch] $TreatPSObjectsLikeDictionaries,
        [Switch] $PassThru
    )
    
    if ($Null -eq $Object1)
    {
        if ($PassThru)
        {
            $Result = $Object2
        }
        else
        {
            Throw 'Object1 is Null and -PassThru is not specified'
        }
    }
    else
    {
        $Result = $Object1
        
        if ($Null -ne $Object2)
        {
            $Queue = New-Object System.Collections.Queue
            $Queue.Enqueue(@{ Object1 = $Object1; Object2 = $Object2 })
            
            while ($Queue.Count -gt 0)
            {
                $CurrentItemInfo = $Queue.Dequeue()
                $Object1 = $CurrentItemInfo['Object1']
                $Object2 = $CurrentItemInfo['Object2']
                
                if ($TreatPSObjectsLikeDictionaries -and ($Object2 -is [System.Management.Automation.PSCustomObject]))
                {
                    $Hashtable = [Ordered] @{}
                    foreach ($Property in $Object2.PSObject.Properties)
                    {
                        $Hashtable[$Property.Name] = $Property.Value
                    }
                    $Object2 = $Hashtable
                }
                
                if ($Object1 -is [Collections.IList])
                {
                    if ($Object1.IsFixedSize)
                    {
                        Throw 'Cannot modify fixed size lists'
                    }
                    
                    switch ($CollectionOrder)
                    {
                        Object1First
                        {
                            if ($Object2 -is [Collections.ICollection])
                            {
                                $Object1.AddRange($Object2) > $Null
                            }
                            else
                            {
                                $Object1.Add($Object2) > $Null
                            }
                            break
                        }
                        
                        Object2First
                        {
                            $Object1Items = $Object1.ToArray()
                            $Object1.Clear()
                            
                            if ($Object2 -is [Collections.ICollection])
                            {
                                $Object1.AddRange($Object2) > $Null
                            }
                            else
                            {
                                $Object1.Add($Object2) > $Null
                            }
                            
                            $Object1.AddRange($Object1Items)
                            break
                        }
                        
                        default { Throw "Unexpected CollectionOrder: $CollectionOrder" }
                    }
                }
                elseif ($Object1 -is [Collections.IDictionary])
                {
                    if ($Object2 -is [Collections.IDictionary])
                    {
                        foreach ($Key in $Object2.Keys)
                        {
                            if ($Object1.Contains($Key))
                            {
                                if ($Object1[$Key] -is [Collections.IDictionary])
                                {
                                    $Queue.Enqueue(@{ Object1 = $Object1[$Key]; Object2 = $Object2[$Key] }) # Enqueue container for further merging
                                }
                                elseif ($Object1[$Key] -is [Collections.IList])
                                {
                                    if ($Object1[$Key].IsFixedSize)
                                    {
                                        $Object1[$Key] = [Collections.ArrayList] $Object1[$Key] # Convert some fixed size IList to ArrayList
                                    }
                                    
                                    $Queue.Enqueue(@{ Object1 = $Object1[$Key]; Object2 = $Object2[$Key] }) # Enqueue container for further merging
                                }
                                else
                                {
                                    switch ($OverrideStrategy)
                                    {
                                        Object1Wins { break } # Nothing to do here; we do not change the existing value in Object1
                                        Object2Wins { $Object1[$Key] = $Object2[$Key]; break }
                                        default { Throw "Unexpected OverrideStrategy: $OverrideStrategy" }
                                    }
                                }
                            }
                            else
                            {
                                $Object1[$Key] = $Object2[$Key]
                            }
                        }
                    }
                    else
                    {
                        Throw "Unsupported object type (right side): $($Object2.GetType().FullName)"
                    }
                }
                elseif ($TreatPSObjectsLikeDictionaries -and ($Object1 -is [System.Management.Automation.PSCustomObject]))
                {
                    $Object1PropertiesByName = [Ordered] @{}
                    foreach ($Property in $Object1.PSObject.Properties)
                    {
                        $Object1PropertiesByName[$Property.Name] = $Property.Value
                    }
                    
                    if ($Object2 -is [Collections.IDictionary])
                    {
                        foreach ($Key in $Object2.Keys)
                        {
                            if ($Object1PropertiesByName.Contains($Key))
                            {
                                if ($Object1.$Key -is [Collections.IDictionary])
                                {
                                    $Queue.Enqueue(@{ Object1 = $Object1.$Key; Object2 = $Object2[$Key] }) # Enqueue container for further merging
                                }
                                elseif ($Object1.$Key -is [Collections.IList])
                                {
                                    if ($Object1.$Key.IsFixedSize)
                                    {
                                        $Object1.$Key = [Collections.ArrayList] $Object1.$Key # Convert some fixed size IList to ArrayList
                                    }
                                    
                                    $Queue.Enqueue(@{ Object1 = $Object1.$Key; Object2 = $Object2[$Key] }) # Enqueue container for further merging
                                }
                                else
                                {
                                    switch ($OverrideStrategy)
                                    {
                                        Object1Wins { break } # Nothing to do here; we do not change the existing value in Object1
                                        Object2Wins { $Object1.$Key = $Object2[$Key]; break }
                                        default { Throw "Unexpected OverrideStrategy: $OverrideStrategy" }
                                    }
                                }
                            }
                            else
                            {
                                Add-Member -InputObject $Object1 -MemberType NoteProperty -Name $Key -Value $Object2[$Key]
                            }
                        }
                    }
                    else
                    {
                        Throw "Unsupported object type (right side): $($Object2.GetType().FullName)"
                    }
                }
                else
                {
                    Throw "Unsupported object type (left side): $($Object1.GetType().FullName)"
                }
            }
        }
    }
    
    if ($PassThru)
    {
        $Result
    }
}
#endregion

$ProfileDataFilePath = "$PSScriptRoot\ProfileData.yaml"
$ProfileData = @{}
try
{
    $ProfileData = Get-Content $ProfileDataFilePath -Raw | ConvertFrom-YAMLQuickly
}
catch
{
    Write-Warning "Could not load ProfileData from file [$ProfileDataFilePath]:`r`n$($_.Exception.Message)"
}

$IncludeInfoSetsQueue = New-Object Collections.Queue
try
{
    foreach ($IncludeInfoSet in $ProfileData['Includes'])
    {
        $IncludeInfoSetsQueue.Enqueue($IncludeInfoSet)
    }
}
catch {}

$LoadedProfileDataFilePathsHelper = @{}
while ($IncludeInfoSetsQueue.Count -gt 0)
{
    $IncludeInfoSet = $IncludeInfoSetsQueue.Dequeue()
    $IncludeInfoSet['Override'] = $IncludeInfoSet['Override'] -and [Bool]::Parse($IncludeInfoSet['Override']) # Convert to boolean
    $IncludeFilePath = $IncludeInfoSet.FilePath
    
    try
    {
        $IncludeFilePath = $ExecutionContext.InvokeCommand.ExpandString($IncludeFilePath)
        $IncludeFilePathFull = (Get-Item $IncludeFilePath).FullName
        
        if ($LoadedProfileDataFilePathsHelper.ContainsKey($IncludeFilePathFull))
        {
            Write-Warning "Cycle detected in ProfileData includes. Not including again: $IncludeFilePathFull"
            continue
        }
        
        $AdditionalProfileData = Get-Content $IncludeFilePath -Raw | ConvertFrom-YAMLQuickly
        
        try
        {
            foreach ($AdditionalIncludeInfoSet in $AdditionalProfileData['Includes'])
            {
                $AdditionalIncludeInfoSet['Override'] = $AdditionalIncludeInfoSet['Override'] -and [Bool]::Parse($AdditionalIncludeInfoSet['Override']) # Convert to boolean
                $AdditionalIncludeInfoSet['Override'] = $AdditionalIncludeInfoSet['Override'] -and $IncludeInfoSet['Override'] # Only if 'both agree' -> override
                $IncludeInfoSetsQueue.Enqueue($AdditionalIncludeInfoSet)
            }
        }
        catch {}
        $AdditionalProfileData.Remove('Includes')
        
        $OverrideStrategy = if ($IncludeInfoSet['Override']) { 'Object2Wins' } else { 'Object1Wins' }
        $CollectionOrder = if ($IncludeInfoSet['Override']) { 'Object2First' } else { 'Object1First' }
        Merge-Object -Object1 $ProfileData -Object2 $AdditionalProfileData -OverrideStrategy $OverrideStrategy -CollectionOrder $CollectionOrder
        
        $LoadedProfileDataFilePathsHelper[$IncludeFilePathFull] = $True
    }
    catch
    {
        Write-Warning "Could not load included ProfileData from file [$IncludeFilePath]:`r`n$($_.Exception.Message)"
    }
}

#region -- Credential functions
Function Setup-KeePassPSCredential
{
    [CmdletBinding(DefaultParameterSetName='EncryptWithUserKey')]
    Param(
        [Parameter(ParameterSetName='EncryptWithUserKey')] [ValidateSet($True)] [Switch] $EncryptWithUserKey,
        
        [Parameter(ParameterSetName='EncryptWithMachineKey')] [ValidateSet($True)] [Switch] $EncryptWithMachineKey,
        
        [Parameter(ParameterSetName='EncryptWithCertificate')] [ValidateSet($True)] [Switch] $EncryptWithCertificate,
        [Parameter(ParameterSetName='EncryptWithCertificate', Mandatory=$True)] [String] $CertificatePath,
        
        [Parameter(ParameterSetName='PlainText')] [ValidateSet($True)] [Switch] $PlainText
    )
    
    $Key = Generate-CryptoRandomBytes -LengthBits 256 -AsBase64
    $KeySecretString = $Key | ConvertTo-SecretString -DecodeBase64 @PSBoundParameters
    $Result = Associate-KeePassHTTP -Key $Key | ForEach-Object { [PSCustomObject] @{
        KeySecretString = $KeySecretString
        ID = $_.Id
    }}
    
    Write-Host -F Green ("KeePassAccessKeySecretString: $($Result.KeySecretString)")
    Write-Host -F Green ("KeePassAccessID: $($Result.ID)")
}

Function Get-KeePassPSCredential
{
    Param(
        [String] $Name
    )
    
    MakeSure-KeePassFileIsOpened
    
    try
    {
        $Key = $ProfileData['Generic']['KeePassAccessKeySecretString'] | ConvertFrom-SecretString -OutBase64
        $ID = $ProfileData['Generic']['KeePassAccessID']
    }
    catch
    {
        Throw 'Could not get KeePassAccessKeySecretString and/or KeePassAccessID from ProfileData'
    }
    
    $KeePassEntries = Get-KeePassHTTPEntry -Key $Key -ID $ID -Filter '#PowerShellCredential'
    
    if ($Name)
    {
        $KeePassEntries = $KeePassEntries | Where-Object Name -like $Name
    }
    
    foreach ($KeePassEntry in $KeePassEntries)
    {
        $Username = $KeePassEntry.Username
        if (! $Username)
        {
            $Username = ' '
        }
        New-Object PSCredential $Username, $KeePassEntry.Password | Add-Member -MemberType NoteProperty -Name KeePassName -Value $KeePassEntry.Name -PassThru
    }
}

Function Set-KeePassPSCredential
{
    # TODO: HIGH: Naming
    # TODO: HIGH: Update instead new
    
    Param(
        [Parameter(Mandatory=$True)] [PSCredential] $Credential,
        [Parameter(Mandatory=$True)] [String] $Name
    )
    
    $Key = $KeePassAccessKey | ConvertFrom-SecretString -OutBase64
    
    New-KeePassHTTPEntry -Key $Key -ID $KeePassAccessID -Username $Credential.Username -Password $Credential.GetNetworkCredential().Password -URL $Name
}

Function Load-KeePassPSCredentials
{
    try
    {
        foreach ($Credential in (Get-KeePassPSCredential))
        {
            $FunctionContent = @'
$CS = '@@CredentialString@@'
$CS | Convert-CredentialFromString
'@
            
            $FunctionContent = $FunctionContent.Replace('@@CredentialString@@', (Convert-CredentialToString $Credential))
            Set-Content -LiteralPath "Function:\Global:cr-kp-$($Credential.KeePassName -replace '\s', '')" -Value $FunctionContent
        }
    }
    catch
    {
        Write-Host -F Magenta "No access to KeePass credentials:`r`n$($_.Exception.Message)"
    }
}

Set-Alias -Name cr-kp -Value Get-KeePassPSCredential -Scope Global

Function MakeSure-KeePassFileIsOpened
{
    $KeePassExeFilePath = try { $ProfileData['Generic']['KeePassExeFilePath'] } catch {}
    $KeePassFilePath = try { $ProfileData['Generic']['KeePassFilePath'] } catch {}
    
    if ($KeePassFilePath)
    {
        $KeePassProcess = Get-Process -Name KeePass -EA SilentlyContinue
        if ($Null -eq $KeePassProcess)
        {
            & $KeePassExeFilePath $KeePassFilePath
        }
    }
}

Function Generate-ScriptBlockFromCredentialInfo
{
    Param(
        [Parameter(Mandatory=$True)] [Object] $CredentialInfo
    )
    
    if ($CredentialInfo -is [String])
    {
        $ScriptBlockContent = @'
& ([ScriptBlock]::Create(@'
@@Command@@
@@HereDocEnd@@))
'@
        
        $ScriptBlockContent = $ScriptBlockContent.Replace('@@Command@@', $CredentialInfo)
        $ScriptBlockContent = $ScriptBlockContent.Replace('@@HereDocEnd@@', "'@")
    }
    else
    {
        $Username = $CredentialInfo['Username']
        $PasswordSecretString = $CredentialInfo['PasswordSecretString']
        
        $ScriptBlockContent = @'
$Username = '@@Username@@'
$Password = '@@PasswordSecretString@@' | ConvertFrom-SecretString | Convert-PlainTextStringToSecureString
New-Object PSCredential $Username, $Password
'@
        
        $ScriptBlockContent = $ScriptBlockContent.Replace('@@Username@@', $Username)
        $ScriptBlockContent = $ScriptBlockContent.Replace('@@PasswordSecretString@@', $PasswordSecretString)
    }
    
    [ScriptBlock]::Create($ScriptBlockContent)
}

Function Load-CredentialsFromProfileData
{
    [CmdletBinding()]
    Param()
    
    try
    {
        $CredentialNames = try { $ProfileData['Credentials'].Keys } catch {}
        
        foreach ($CredentialName in $CredentialNames)
        {
            try
            {
                $CredentialInfo = $ProfileData['Credentials'][$CredentialName]
                
                $ScriptBlock = Generate-ScriptBlockFromCredentialInfo $CredentialInfo
                Set-Content -LiteralPath "Function:\Global:cr-$CredentialName" -Value $ScriptBlock
            }
            catch
            {
                Write-Host -F Magenta "Could not load credential [$CredentialName] from ProfileData:`r`n$($_.Exception.Message)"
            }
        }
    }
    catch
    {
        Write-Host -F Magenta "Could not load credentials from ProfileData:`r`n$($_.Exception.Message)"
    }
}

Function Read-HostAsSecretStringToClipboard
{
    Read-Host -AsSecureString | Convert-SecureStringToPlainText | ConvertTo-SecretString | Set-Clipboard
}

Function Get-CredentialForHostname
{
    Param(
        [Parameter(Mandatory=$True)] [String] $Hostname,
        [PSCredential] $DefaultCredential
    )
    
    $Result = $DefaultCredential
    try
    {
        $HostnameRegexes = try { $ProfileData['CredentialsByHostname'].Keys } catch {}
        foreach ($HostnameRegex in $HostnameRegexes)
        {
            if ($Hostname -match "^$HostnameRegex$")
            {
                $CredentialInfo = $ProfileData['CredentialsByHostname'][$HostnameRegex]
                $Result = & (Generate-ScriptBlockFromCredentialInfo $CredentialInfo)
                break
            }
        }
    }
    catch
    {
        Write-Host -F Magenta "Could not get credential for hostname [$Hostname] from ProfileData:`r`n$($_.Exception.Message)"
    }
    
    $Result
}
#endregion

#region -- Generic Functions
Function npp { & 'C:\Program Files (x86)\Notepad++\notepad++.exe' @Args }

Function powercli
{
    if (! (Get-Module VMware.VimAutomation.Core))
    {
        Import-Module VMware.VimAutomation.Core
        . $Profile
    }
    
    Write-Host -F White "Connecting to 192.168.1.11"
    Connect-VIServer 192.168.1.11 -Credential (cr-myvc) -WA SilentlyContinue > $Null
}

Function GenStrings($InputValues, $FormatString) { $InputValues | %{ $FormatString -f $_ } }

Function Global:prompt
{
    $TextColor = 'Green'
    if ([Console]::BackgroundColor -eq 'White')
    {
        $TextColor = 'Blue'
    }
    Write-Host ("$(Get-Date -Format 'mm:ss') ") -NoNewline -ForegroundColor DarkGray
    Write-Host ("$(Get-Location | Split-Path -Leaf)>") -NoNewline -ForegroundColor $TextColor
    " "
}
#endregion

#region -- Remote Connect Functions
Function ssh
{
    Param(
        [Parameter(Mandatory=$True)] [String[]] $Hostnames,
        [PSCredential] $Credential
    )
    
    $PuTTYExeFilePath = try { $ProfileData['Generic']['PuTTYExeFilePath'] } catch { Throw 'Generic.PuTTYExeFilePath is not defined in ProfileData' }
    
    $DefaultCredential = try { cr-default-ssh } catch {}
    
    $CanContinue = $True
    $CredentialsByHostname = @{}
    foreach ($Hostname in $Hostnames)
    {
        if (! $PSBoundParameters.ContainsKey('Credential'))
        {
            $Credential = Get-CredentialForHostname -Hostname $Hostname -DefaultCredential $DefaultCredential   # Implicit conversion to [PSCredential]
        }
        
        if ($Null -eq $Credential)
        {
            Write-Host "No credential to use for host: $Hostname"
            $CanContinue = $False
        }
        
        $CredentialsByHostname[$HostName] = $Credential
    }
    
    if (! $CanContinue)
    {
        return
    }
    
    foreach ($Hostname in $Hostnames)
    {
        $Credential = $CredentialsByHostname[$Hostname]
        & $PuTTYExeFilePath "$($Credential.Username)@$Hostname" -pw $Credential.GetNetworkCredential().Password
    }
}

Function winrm
{
    Param(
        [Parameter(Mandatory=$True)] [String] $Hostname,
        [PSCredential] $Credential
    )
    
    $DefaultCredential = try { cr-default-winrm } catch {}
    
    if (! $PSBoundParameters.ContainsKey('Credential'))
    {
        $Credential = Get-CredentialForHostname -Hostname $Hostname -DefaultCredential $DefaultCredential   # Implicit conversion to [PSCredential]
    }
    
    if ($Null -eq $Credential)
    {
        Write-Host "No credential to use for host: $Hostname"
    }
    else
    {
        Enter-PSSession -ComputerName $Hostname -Credential $Credential
    }
}

Function rdp
{
    Param(
        [Parameter(Mandatory=$True)] [String[]] $Hostnames,
        [PSCredential] $Credential
    )
    
    $DefaultCredential = try { cr-default-rdp } catch {}
    
    $CanContinue = $True
    $CredentialsByHostname = @{}
    foreach ($Hostname in $Hostnames)
    {
        if (! $PSBoundParameters.ContainsKey('Credential'))
        {
            $Credential = Get-CredentialForHostname -Hostname $Hostname -DefaultCredential $DefaultCredential   # Implicit conversion to [PSCredential]
        }
        
        if ($Null -eq $Credential)
        {
            Write-Host "No credential to use for host: $Hostname"
            $CanContinue = $False
        }
        
        $CredentialsByHostname[$HostName] = $Credential
    }
    
    if (! $CanContinue)
    {
        return
    }
    
    foreach ($Hostname in $Hostnames)
    {
        $Credential = $CredentialsByHostname[$Hostname]
        Connect-Mstsc -ComputerName $Hostname -Credential $Credential -FullScreen
    }
}

Function vsc
{
    Param(
        [String[]] $Hostnames,
        [PSCredential] $Credential
    )
    
    $VSphereClientExeFilePath = try { $ProfileData['Generic']['VSphereClientExeFilePath'] } catch { Throw 'Generic.VSphereClientExeFilePath is not defined in ProfileData' }
    
    if ($Null -eq $Hostnames)
    {
        $DefaultVCenterServerHostname = try { $ProfileData['Generic']['DefaultVCenterServerHostname'] } catch {}
        if ($Null -eq $DefaultVCenterServerHostname)
        {
            Throw 'No hostnames specified'
        }
        $Hostnames = $DefaultVCenterServerHostname
    }
    
    $DefaultCredential = try { cr-default-vsc } catch {}
    
    $CanContinue = $True
    $CredentialsByHostname = @{}
    foreach ($Hostname in $Hostnames)
    {
        if (! $PSBoundParameters.ContainsKey('Credential'))
        {
            $Credential = Get-CredentialForHostname -Hostname $Hostname -DefaultCredential $DefaultCredential   # Implicit conversion to [PSCredential]
        }
        
        if ($Null -eq $Credential)
        {
            Write-Host "No credential to use for host: $Hostname"
            $CanContinue = $False
        }
        
        $CredentialsByHostname[$HostName] = $Credential
    }
    
    if (! $CanContinue)
    {
        return
    }
    
    foreach ($Hostname in $Hostnames)
    {
        $Credential = $CredentialsByHostname[$Hostname]
        & $VSphereClientExeFilePath -i -s $Hostname -u $Credential.Username -p $Credential.GetNetworkCredential().Password
    }
}

Function Connect-Mstsc
{
    <#   
    .SYNOPSIS   
    Function to connect an RDP session without the password prompt
        
    .DESCRIPTION 
    This function provides the functionality to start an RDP session without having to type in the password
        
    .PARAMETER ComputerName
    This can be a single computername or an array of computers to which RDP session will be opened

    .PARAMETER User
    The user name that will be used to authenticate

    .PARAMETER Password
    The password that will be used to authenticate

    .PARAMETER Credential
    The PowerShell credential object that will be used to authenticate against the remote system

    .PARAMETER Admin
    Sets the /admin switch on the mstsc command: Connects you to the session for administering a server

    .PARAMETER MultiMon
    Sets the /multimon switch on the mstsc command: Configures the Remote Desktop Services session monitor layout to be identical to the current client-side configuration 

    .PARAMETER FullScreen
    Sets the /f switch on the mstsc command: Starts Remote Desktop in full-screen mode

    .PARAMETER Public
    Sets the /public switch on the mstsc command: Runs Remote Desktop in public mode

    .PARAMETER Width
    Sets the /w:<width> parameter on the mstsc command: Specifies the width of the Remote Desktop window

    .PARAMETER Height
    Sets the /h:<height> parameter on the mstsc command: Specifies the height of the Remote Desktop window

    .NOTES   
    Name:        Connect-Mstsc
    Author:      Jaap Brasser
    DateUpdated: 2016-10-28
    Version:     1.2.5
    Blog:        http://www.jaapbrasser.com

    .LINK
    http://www.jaapbrasser.com

    .EXAMPLE   
    . .\Connect-Mstsc.ps1
        
    Description 
    -----------     
    This command dot sources the script to ensure the Connect-Mstsc function is available in your current PowerShell session

    .EXAMPLE   
    Connect-Mstsc -ComputerName server01 -User contoso\jaapbrasser -Password (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force)

    Description 
    -----------     
    A remote desktop session to server01 will be created using the credentials of contoso\jaapbrasser

    .EXAMPLE   
    Connect-Mstsc server01,server02 contoso\jaapbrasser (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force)

    Description 
    -----------     
    Two RDP sessions to server01 and server02 will be created using the credentials of contoso\jaapbrasser

    .EXAMPLE   
    server01,server02 | Connect-Mstsc -User contoso\jaapbrasser -Password (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force) -Width 1280 -Height 720

    Description 
    -----------     
    Two RDP sessions to server01 and server02 will be created using the credentials of contoso\jaapbrasser and both session will be at a resolution of 1280x720.

    .EXAMPLE   
    server01,server02 | Connect-Mstsc -User contoso\jaapbrasser -Password (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force) -Wait

    Description 
    -----------     
    RDP sessions to server01 will be created, once the mstsc process is closed the session next session is opened to server02. Using the credentials of contoso\jaapbrasser and both session will be at a resolution of 1280x720.

    .EXAMPLE   
    Connect-Mstsc -ComputerName server01:3389 -User contoso\jaapbrasser -Password (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force) -Admin -MultiMon

    Description 
    -----------     
    A RDP session to server01 at port 3389 will be created using the credentials of contoso\jaapbrasser and the /admin and /multimon switches will be set for mstsc

    .EXAMPLE   
    Connect-Mstsc -ComputerName server01:3389 -User contoso\jaapbrasser -Password (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force) -Public

    Description 
    -----------     
    A RDP session to server01 at port 3389 will be created using the credentials of contoso\jaapbrasser and the /public switches will be set for mstsc

    .EXAMPLE
    Connect-Mstsc -ComputerName 192.168.1.10 -Credential $Cred

    Description 
    -----------     
    A RDP session to the system at 192.168.1.10 will be created using the credentials stored in the $cred variable.

    .EXAMPLE   
    Get-AzureVM | Get-AzureEndPoint -Name 'Remote Desktop' | ForEach-Object { Connect-Mstsc -ComputerName ($_.Vip,$_.Port -join ':') -User contoso\jaapbrasser -Password (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force) }

    Description 
    -----------     
    A RDP session is started for each Azure Virtual Machine with the user contoso\jaapbrasser and password supersecretpw

    .EXAMPLE
    PowerShell.exe -Command "& {. .\Connect-Mstsc.ps1; Connect-Mstsc server01 contoso\jaapbrasser (ConvertTo-SecureString 'supersecretpw' -AsPlainText -Force) -Admin}"

    Description
    -----------
    An remote desktop session to server01 will be created using the credentials of contoso\jaapbrasser connecting to the administrative session, this example can be used when scheduling tasks or for batch files.
    #>
    
    [cmdletbinding(SupportsShouldProcess,DefaultParametersetName='UserPassword')]
    param (
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Alias('CN')]
            [string[]]     $ComputerName,
        [Parameter(ParameterSetName='UserPassword',Mandatory=$true,Position=1)]
        [Alias('U')] 
            [string]       $User,
        [Parameter(ParameterSetName='UserPassword',Mandatory=$true,Position=2)]
        [Alias('P')] 
            [string]       $Password,
        [Parameter(ParameterSetName='Credential',Mandatory=$true,Position=1)]
        [Alias('C')]
            [PSCredential] $Credential,
        [Alias('A')]
            [switch]       $Admin,
        [Alias('MM')]
            [switch]       $MultiMon,
        [Alias('F')]
            [switch]       $FullScreen,
        [Alias('Pu')]
            [switch]       $Public,
        [Alias('W')]
            [int]          $Width,
        [Alias('H')]
            [int]          $Height,
        [Alias('WT')]
            [switch]       $Wait
    )

    begin {
        [string]$MstscArguments = ''
        switch ($true) {
            {$Admin}      {$MstscArguments += '/admin '}
            {$MultiMon}   {$MstscArguments += '/multimon '}
            {$FullScreen} {$MstscArguments += '/f '}
            {$Public}     {$MstscArguments += '/public '}
            {$Width}      {$MstscArguments += "/w:$Width "}
            {$Height}     {$MstscArguments += "/h:$Height "}
        }

        if ($Credential) {
            $User     = $Credential.UserName
            $Password = $Credential.GetNetworkCredential().Password
        }
    }
    process {
        foreach ($Computer in $ComputerName) {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $Process = New-Object System.Diagnostics.Process
            
            # Remove the port number for CmdKey otherwise credentials are not entered correctly
            if ($Computer.Contains(':')) {
                $ComputerCmdkey = ($Computer -split ':')[0]
            } else {
                $ComputerCmdkey = $Computer
            }

            $ProcessInfo.FileName    = "$($env:SystemRoot)\system32\cmdkey.exe"
            $ProcessInfo.Arguments   = "/generic:TERMSRV/$ComputerCmdkey /user:$User /pass:$($Password)"
            $ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $Process.StartInfo = $ProcessInfo
            if ($PSCmdlet.ShouldProcess($ComputerCmdkey,'Adding credentials to store')) {
                [void]$Process.Start()
            }

            $ProcessInfo.FileName    = "$($env:SystemRoot)\system32\mstsc.exe"
            $ProcessInfo.Arguments   = "$MstscArguments /v $Computer"
            $ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
            $Process.StartInfo       = $ProcessInfo
            if ($PSCmdlet.ShouldProcess($Computer,'Connecting mstsc')) {
                [void]$Process.Start()
                if ($Wait) {
                    $null = $Process.WaitForExit()
                }       
            }
        }
    }
}
#endregion

#region -- Completion Functions
Function Complete-Hostname
{
    Param(
        [Parameter(Mandatory=$True)] [String] $WordToComplete
    )
    
    $NetworkInfoSets = & {
        $HostnameCompletionCSVFiles = try { $ProfileData['Generic']['HostnameCompletionCSVFiles'] } catch {}
        
        if ($HostnameCompletionCSVFiles)
        {
            $HostnameCompletionCSVFiles = $ExecutionContext.InvokeCommand.ExpandString($HostnameCompletionCSVFiles) # Resolve variables
            ls $HostnameCompletionCSVFiles -PV File | %{
                Import-Csv -Delim ';' $File.FullName | %{ $_ | Add-Member -Type NoteProperty -Name Source -Value $File.Name.Replace('.csv', '') -PassThru -Force }
            }
        }
        
        foreach ($HostDefinition in $ProfileData['HostDefinitions'])
        {
            [PSCustomObject] @{
                'IP-address' = $HostDefinition['IP-address']
                FQDN = $HostDefinition['FQDN']
                Description = $HostDefinition['Description']
                State = $HostDefinition['State']
                Source = 'ProfileData'
            }
        }
    } | Sort FQDN
    
    if ($WordToComplete -like '*`*')
    {
        $ActualWordToComplete = $WordToComplete.Remove($WordToComplete.Length - 1)
        $CandidateNetworkInfoSets = $NetworkInfoSets | ?{
            "$($_.'IP-address')$($_.FQDN)$($_.Description)$($_.State)$($_.Source)" -like "*$ActualWordToComplete*"
        }
        $CompletionNetworkInfoSets = $CandidateNetworkInfoSets | Out-GridView -PassThru
        $CompletionItems = $CompletionNetworkInfoSets | %{ if ($_.FQDN) { $_.FQDN } else { $_.'IP-address' } }
        $CompletionItemsAllIPs = $CompletionNetworkInfoSets | Select -ExpandProperty IP-address
        @(
            $CompletionItems -join ', '
            $CompletionItemsAllIPs -join ', '
        )
    }
    else
    {
        $CompletionItems = & {
            $NetworkInfoSets | Select -ExpandProperty FQDN
            $NetworkInfoSets | Select -ExpandProperty IP-address
        } | Sort -Unique
        $CompletionItems | ?{ $_ -like "*$WordToComplete*" }
    }
}

$HostnameCompletionScriptBlock = {
    Param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)
    Complete-Hostname -WordToComplete $WordToComplete
}

$NativeHostnameCompletionScriptBlock = {
    Param($WordToComplete, $CommandAst, $CursorPosition)
    Complete-Hostname -WordToComplete $WordToComplete
}

# Register-ArgumentCompleter -CommandName ssh -ParameterName Hostnames -ScriptBlock $HostnameCompletionScriptBlock
# Register-ArgumentCompleter -CommandName winrm -ParameterName Hostname -ScriptBlock $HostnameCompletionScriptBlock
# Register-ArgumentCompleter -CommandName rdp -ParameterName Hostnames -ScriptBlock $HostnameCompletionScriptBlock

Register-ArgumentCompleter -ParameterName ComputerName -ScriptBlock $HostnameCompletionScriptBlock
Register-ArgumentCompleter -ParameterName Hostname -ScriptBlock $HostnameCompletionScriptBlock
Register-ArgumentCompleter -ParameterName Hostnames -ScriptBlock $HostnameCompletionScriptBlock
Register-ArgumentCompleter -CommandName ping -ScriptBlock $NativeHostnameCompletionScriptBlock

Register-ArgumentCompleter -CommandName Get-KeePassPSCredential -ParameterName Name -ScriptBlock {
    Param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)
    Get-KeePassPSCredential | ? KeePassName -like *$WordToComplete* | Select -ExpandProperty KeePassName
}

#endregion

Load-CredentialsFromProfileData
# Load-KeePassPSCredentials

Write-Host -F DarkGray "Profile loaded in $([Int] $StopWatch.Elapsed.TotalMilliseconds) ms`r`n"

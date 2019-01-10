$FileEncryption = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

public class FileEncryption {

    public static int encryptFile (string inputFilePath, string outputFilePath, SecureString key) {
        SecureStringBytes ssb = new SecureStringBytes (key);
        byte[] keyByteArr = ssb.GetBytes ();
        using (RijndaelManaged AES = new RijndaelManaged ()) {
            AES.Key = keyByteArr;
            using (FileStream fsInput = new FileStream (inputFilePath, FileMode.Open)) {
                string encryptedFile = outputFilePath;
                using (MemoryStream msEncrypt = new MemoryStream ()) {
                    ICryptoTransform encryptor = AES.CreateEncryptor (AES.Key, AES.IV);
                    using (CryptoStream csEncrypt = new CryptoStream (msEncrypt, encryptor, CryptoStreamMode.Write)) {
                        msEncrypt.Write(AES.IV, 0, AES.IV.Length);
                        int data;
                        while ((data = fsInput.ReadByte ()) != -1) {
                            csEncrypt.WriteByte ((byte) data);
                        }
                        csEncrypt.FlushFinalBlock();
                    }
                    byte[] encryptedData = msEncrypt.ToArray();
                    File.WriteAllBytes(encryptedFile, encryptedData);
                }
            }
        }

        ssb.Dispose ();
        return 0;
    }

    public static int decryptFile (string inputFilePath, string outputFilePath, SecureString key) {
        SecureStringBytes ssb = new SecureStringBytes (key);
        byte[] keyByteArr = ssb.GetBytes ();
        using (RijndaelManaged AES = new RijndaelManaged ()) {
            AES.Key = keyByteArr;
            using (FileStream fsInput = new FileStream (inputFilePath, FileMode.Open)) {
                string decryptedFile = outputFilePath;
                byte[] IV = new byte[AES.IV.Length];
                fsInput.Read(IV, 0, AES.IV.Length);
                AES.IV = IV;
                using (MemoryStream msDecrypt = new MemoryStream() ) {
                    ICryptoTransform decryptor = AES.CreateDecryptor (AES.Key, AES.IV);
                    using (CryptoStream csDecrypt = new CryptoStream (fsInput, decryptor, CryptoStreamMode.Read)) {
                        int data;
                        while ((data = csDecrypt.ReadByte ()) != -1) {
                            msDecrypt.WriteByte ((byte) data);
                        }
                    }
                    byte[] decryptedData = msDecrypt.ToArray();
                    File.WriteAllBytes(decryptedFile, decryptedData);
                }
            }
        }

        ssb.Dispose ();
        return 0;
    }
}

public sealed class SecureStringBytes : IDisposable {
    private SecureString secureString;
    private byte[] bytes;

    public SecureStringBytes (SecureString secureString) {
        if (secureString == null) {
            throw new ArgumentNullException ("secureString");
        }
        this.secureString = secureString;
    }

    public void Clear () {
        if (bytes != null) {
            for (int i = 0; i < bytes.Length; i++) {
                bytes[i] = 0;
            }
            bytes = null;
        }
    }

    public void Dispose () {
        Clear ();
    }

    public byte[] GetBytes () {
        if (bytes == null) {
            bytes = ConvertSecureStringToBytes (secureString);
        }
        return bytes;
    }

    private static byte[] ConvertSecureStringToBytes (SecureString secureString) {
        var result = new byte[secureString.Length * 2];
        IntPtr valuePtr = IntPtr.Zero;
        try {
            valuePtr = Marshal.SecureStringToGlobalAllocUnicode (secureString);
            for (int i = 0; i < secureString.Length; i++) {
                result[i] = Marshal.ReadByte (valuePtr, i * 2);
                result[i + 1] = Marshal.ReadByte (valuePtr, i * 2 + 1);
            }
        } finally {
            Marshal.ZeroFreeGlobalAllocUnicode (valuePtr);
        }

        return result;
    }
}
'@
Add-Type -TypeDefinition $FileEncryption

Function Protect-File{
<#
.SYNOPSIS
Encrypt a file or directory of files with a provided key.

.DESCRIPTION
Encrypt file(s) utilizing AES256 with the RijndaelManaged .NET class.

.PARAMETER Path
A path in string format to the file that needs to be encrypted.

.PARAMETER Key
A user supplied symmetric key to perform the encryption with. If the key is forgotten, you will be unable to decrypt the data.

.PARAMETER Recurse
Utilized to encrypt all the files under a specified directory.

.PARAMETER Force
Utilized to encrypt hidden files when specifying a directory.

.EXAMPLE
Protect-File -Path 'C:\Temp\Test\Test.txt'

.EXAMPLE
Protect-File -Path 'C:\Temp\Test\Test.txt' -Key $Key

.EXAMPLE
Protect-File -Path 'C:\temp\Test' -Recurse -Force

.OUTPUTS
[Void]

.NOTES
Author: Joshua Chase
Last Modified: 31 December 2018
#>
[cmdletbinding()]
Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
    [String[]]$Path,

    [Parameter(Position=1)]
    [SecureString]$Key = (Read-Host "Enter the key to encrypt with: " -AsSecureString),

    [Parameter()]
    [Switch]$Recurse,

    [Parameter()]
    [Switch]$Force
)
    Begin{
        
    #End Begin Block
    }

    Process{
        ForEach ($Entry in $Path){
            If ($Recurse){
                $Directories = Get-ChildItem -Path $Entry -Directory -Force:$Force
                $Files = Get-ChildItem -Path $Entry -File -Force:$Force
                ForEach ($Folder in $Directories){
                    Protect-File -Path $Folder.FullName -Key $Key -Recurse
                }
                ForEach ($Item in $Files){
                    Protect-File -Path $Item.FullName -Key $Key
                }
                Continue
            }
            $PathSplit = $Entry.split('\')
            $OutputFileName = $PathSplit[-1]
            $CurrentPath = $PathSplit[0..($PathSplit.Count - 2)] -join '\'
            $OutputFileName = $OutputFileName | ConvertTo-HexString
            $OutputFilePath = Join-Path $CurrentPath $OutputFileName
            
            Write-Verbose "Entry: [$Entry]"
            Write-Verbose "OutputFilePath: [$OutputFilePath]"

            $Result = [FileEncryption]::encryptFile($Entry, $OutputFilePath, $Key)
            If ($Result -eq 0){
                Remove-Item -Path $Entry -Force
                Write-Verbose "Successfully encrypted $Entry."
            }
            Else{
                Write-Error "Failed to encrypt $Entry."
            }
        }
    #End Process Block
    }

    End{
        $Key = $null
        [System.GC]::Collect()
    #End End Block
    }
}
Export-ModuleMember -Function Protect-File

Function Unprotect-File{
<#
.SYNOPSIS
Decrypt a file or directory of files with a provided key.

.DESCRIPTION
Decrypt file(s) utilizing AES256 with the RijndaelManaged .NET class.

.PARAMETER Path
A path in string format to the file that needs to be decrypted.

.PARAMETER Key
A user supplied symmetric key to perform the decryption with. If the key is forgotten, you will be unable to decrypt the data.

.PARAMETER Recurse
Utilized to decrypt all the files under a specified directory.

.PARAMETER Force
Utilized to decrypt hidden files when specifying a directory.

.EXAMPLE
Unprotect-File -Path 'C:\Temp\Test\Test.txt'

.EXAMPLE
Unprotect-File -Path 'C:\Temp\Test\Test.txt' -Key $Key

.EXAMPLE
Unprotect-File -Path 'C:\temp\Test' -Recurse -Force

.OUTPUTS
[Void]

.NOTES
Author: Joshua Chase
Last Modified: 31 December 2018
#>
[cmdletbinding()]
Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
    [String[]]$Path,

    [Parameter(Position=1)]
    [SecureString]$Key = (Read-Host "Enter the key to decrypt with: " -AsSecureString),

    [Parameter()]
    [Switch]$Recurse,

    [Parameter()]
    [Switch]$Force
)
    Begin{
        
    #End Begin Block
    }

    Process{
        ForEach ($Entry in $Path){
            If ($Recurse){
                $Directories = Get-ChildItem -Path $Entry -Directory -Force:$Force
                $Files = Get-ChildItem -Path $Entry -File -Force:$Force
                ForEach ($Folder in $Directories){
                    Unprotect-File -Path $Folder.FullName -Key $Key -Recurse
                }
                ForEach ($Item in $Files){
                    Unprotect-File -Path $Item.FullName -Key $Key
                }
                Continue
            }
            $PathSplit = $Entry.split('\')
            $OutputFileName = $PathSplit[-1] | ConvertFrom-HexString -NoDelimiter
            $CurrentPath = $PathSplit[0..($PathSplit.Count - 2)] -join '\'
            $OutputFilePath = Join-Path $CurrentPath $OutputFileName

            Write-Verbose "Entry: [$Entry]"
            Write-Verbose "OutputFilePath: [$OutputFilePath]"
            
            $Result = [FileEncryption]::decryptFile($Entry, $OutputFilePath, $Key)
            If ($Result -eq 0){
                Remove-Item -Path $Entry -Force
                Write-Verbose "Successfully decrypted $Entry."
            }
            Else{
                Write-Error "Failed to decrypt $Entry."
            }
        }
    #End Process Block
    }

    End{
        $Key = $null
        [System.GC]::Collect()
    #End End Block
    }
}
Export-ModuleMember -Function Unprotect-File

Function ConvertTo-HexString{
<#
.SYNOPSIS
Converts an ASCII string to hex values.

.DESCRIPTION
Encrypt string by converting it to hex values.

.PARAMETER InputObject
A string that will be converted to hex values.

.EXAMPLE
ConvertTo-HexString -InputObject 'Test String'

.EXAMPLE
ConvertTo-HexString 'Test String'

.OUTPUTS
[System.String]

.NOTES
Author: Joshua Chase
Last Modified: 31 December 2018
#>
[cmdletbinding()]
Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
    [String]$InputObject
)
    $HexCharList = New-Object System.Collections.Generic.List[String]
    $AsciiChars = $InputObject.ToCharArray()
    ForEach ($Char in $AsciiChars){
        $HexChar = [convert]::ToString([byte]$Char,16)
        $HexCharList.Add($HexChar)
    }
    $HexString = $HexCharList -join ''
    Write-Output $HexString
}

Function ConvertFrom-HexString{
<#
.SYNOPSIS
Converts a string of hex values to ASCII characters.

.DESCRIPTION
Decrypt string of hex values to ASCII characters.

.PARAMETER InputObject
A hex string that will be converted to ASCII characters.

.PARAMETER Delimiter
The delimiter that separates out the hex string. Default value is a space.

.PARAMETER NoDelimiter
Utilized when there is no delimiter in the hex string. Will process 2 hex characters together at a time.

.EXAMPLE
ConvertFrom-HexString -InputObject '5465737420537472696e67' -NoDelimiter

.EXAMPLE
ConvertFrom-HexString '54 65 73 74 20 53 74 72 69 6e 67'

.OUTPUTS
[System.String]

.NOTES
Author: Joshua Chase
Last Modified: 31 December 2018
#>
[cmdletbinding(DefaultParameterSetName = 'Delimiter')]
Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
    [String]$InputObject,

    [Parameter(Position=1,ParameterSetName='Delimiter')]
    [String]$Delimiter = ' ',

    [Parameter(ParameterSetName='NoDelimiter')]
    [Switch]$NoDelimiter
)
    
    $AsciiCharList = New-Object System.Collections.Generic.List[char]
    If ($NoDelimiter){
        for ($i = 0; $i -lt $InputObject.Length;$i = $i + 2){
            $HexChar = $InputObject[$i] + $InputObject[($i + 1)]
            $HexChar = [convert]::ToInt16($HexChar,16)
            $AsciiCharList.Add(([char][byte]"$HexChar"))
        }
    }
    Else{
        $HexArray = $InputObject -split "$Delimiter"
        ForEach ($HexChar in $HexArray){
            $HexChar = [convert]::ToInt16($HexChar,16)
            $AsciiCharList.Add(([char][byte]"$HexChar"))
        }
    }
    $AsciiString = $AsciiCharList -join ''
    Write-Output $AsciiString
}
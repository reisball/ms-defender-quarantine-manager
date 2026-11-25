# Test-only helpers for existing plaintext contract assertions. The production
# runbook always writes protected output for list/export.
function New-FixtureRsa {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.KeySize = 2048
    return $rsa
}
function ConvertFrom-FixtureProtectedOutput {
    param([object[]] $Lines, [string] $Action, [object] $Rsa)
    $cipher = $null
    try {
        foreach ($line in $Lines) {
            if ($line -isnot [string] -or -not $line.TrimStart().StartsWith("{")) { continue }
            $record = $line | ConvertFrom-Json
            if ($record.mode -ne "msq-protected-v1") {
                if ($record.error -ne $true) { throw "Unexpected plaintext success." }
                Write-Output $line
                continue
            }
            if ($record.index -eq 0) {
                $key = $Rsa.Decrypt(
                    [Convert]::FromBase64String($record.wrapped_key),
                    [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
                )
                $cipher = [System.Security.Cryptography.AesGcm]::new($key)
            }
            $index = $record.index
            $final = if ($record.final) { 1 } else { 0 }
            $aad = [Text.Encoding]::ASCII.GetBytes("msq-protected-v1:${Action}:${index}:$final")
            $bytes = [Convert]::FromBase64String($record.ciphertext)
            $plain = [byte[]]::new($bytes.Length)
            $cipher.Decrypt(
                [Convert]::FromBase64String($record.nonce), $bytes,
                [Convert]::FromBase64String($record.tag), $plain, $aad
            )
            Write-Output ([Text.Encoding]::UTF8.GetString($plain))
        }
    } finally {
        if ($null -ne $cipher) { $cipher.Dispose() }
    }
}

$ErrorActionPreference = "Stop"

$runbookPath = Join-Path $PSScriptRoot "runbook.ps1"
$source = [System.IO.File]::ReadAllText($runbookPath)
$helperStart = $source.IndexOf("function Write-ErrorResult")
$stepOne = $source.IndexOf("# Step 1: Validate webhook input")

if ($helperStart -lt 0 -or $stepOne -le $helperStart) {
    throw "Could not locate the runbook helper section."
}

Invoke-Expression $source.Substring($helperStart, $stepOne - $helperStart)

function Assert-AcceptsBase64 {
    param(
        [string] $Name,
        [AllowEmptyString()]
        [string] $Payload,
        [long] $ExpectedDecodedSize
    )

    $info = Get-Base64PayloadInfo -Base64 $Payload
    if ($info.DecodedSize -ne $ExpectedDecodedSize) {
        throw "$Name decoded-size mismatch: expected $ExpectedDecodedSize, got $($info.DecodedSize)."
    }
}

function Assert-RejectsBase64 {
    param(
        [string] $Name,
        [AllowEmptyString()]
        [string] $Payload,
        [string] $ExpectedMessage
    )

    try {
        $null = Get-Base64PayloadInfo -Base64 $Payload
    } catch {
        if ($_.Exception.Message -ne $ExpectedMessage) {
            throw "$Name returned '$($_.Exception.Message)', expected '$ExpectedMessage'."
        }
        return
    }
    throw "$Name unexpectedly accepted an invalid Base64 payload."
}

$validCases = @(
    @{ Name = "no padding"; Plain = "TWFu"; Wrapped = "TW`r`nFu"; Size = 3 },
    @{ Name = "single padding"; Plain = "TWE="; Wrapped = "TW`r`nE="; Size = 2 },
    @{ Name = "double padding"; Plain = "TQ=="; Wrapped = "TQ`r`n=="; Size = 1 }
)

foreach ($case in $validCases) {
    Assert-AcceptsBase64 `
        -Name "$($case.Name), unwrapped" `
        -Payload $case.Plain `
        -ExpectedDecodedSize $case.Size
    Assert-AcceptsBase64 `
        -Name "$($case.Name), MIME wrapped" `
        -Payload $case.Wrapped `
        -ExpectedDecodedSize $case.Size
}

$allowedWhitespaceCases = @(
    @{ Name = "HTAB"; Payload = "T`tQ==" },
    @{ Name = "LF"; Payload = "T`nQ==" },
    @{ Name = "CR"; Payload = "T`rQ==" },
    @{ Name = "Space"; Payload = "T Q==" },
    @{ Name = "combined"; Payload = "T`tQ`r`n= =" }
)
foreach ($case in $allowedWhitespaceCases) {
    Assert-AcceptsBase64 `
        -Name "allowed whitespace $($case.Name)" `
        -Payload $case.Payload `
        -ExpectedDecodedSize 1
}

$unsupportedWhitespaceCases = @(
    @{ Name = "vertical tab"; Character = [char]0x000B },
    @{ Name = "form feed"; Character = [char]0x000C },
    @{ Name = "next line"; Character = [char]0x0085 },
    @{ Name = "no-break space"; Character = [char]0x00A0 },
    @{ Name = "line separator"; Character = [char]0x2028 },
    @{ Name = "ideographic space"; Character = [char]0x3000 }
)
foreach ($case in $unsupportedWhitespaceCases) {
    Assert-RejectsBase64 `
        -Name "$($case.Name), without allowed whitespace" `
        -Payload ("TQ" + $case.Character + "==") `
        -ExpectedMessage "Base64 content contains unsupported whitespace."
    Assert-RejectsBase64 `
        -Name "$($case.Name), with allowed LF" `
        -Payload ("TQ" + $case.Character + "=`n=") `
        -ExpectedMessage "Base64 content contains unsupported whitespace."
}

$invalidCharacterCases = @(
    @{ Name = "invalid character at start"; Plain = "!WFu"; Wrapped = "!W`r`nFu" },
    @{ Name = "invalid character in middle"; Plain = "TW!u"; Wrapped = "TW`r`n!u" },
    @{ Name = "invalid character at end"; Plain = "TWF!"; Wrapped = "TW`r`nF!" }
)

foreach ($case in $invalidCharacterCases) {
    Assert-RejectsBase64 `
        -Name "$($case.Name), unwrapped" `
        -Payload $case.Plain `
        -ExpectedMessage "Base64 content contains an invalid character."
    Assert-RejectsBase64 `
        -Name "$($case.Name), MIME wrapped" `
        -Payload $case.Wrapped `
        -ExpectedMessage "Base64 content contains an invalid character."
}

$invalidPaddingCases = @(
    @{ Name = "padding in middle"; Plain = "TW=F"; Wrapped = "TW`r`n=F" },
    @{ Name = "more than two padding characters"; Plain = "TQ==="; Wrapped = "TQ=`r`n==" },
    @{ Name = "data after padding"; Plain = "TQ==A"; Wrapped = "TQ==`r`nA" }
)

foreach ($case in $invalidPaddingCases) {
    Assert-RejectsBase64 `
        -Name "$($case.Name), unwrapped" `
        -Payload $case.Plain `
        -ExpectedMessage "Base64 padding is invalid."
    Assert-RejectsBase64 `
        -Name "$($case.Name), MIME wrapped" `
        -Payload $case.Wrapped `
        -ExpectedMessage "Base64 padding is invalid."
}

Assert-RejectsBase64 `
    -Name "length not divisible by four, unwrapped" `
    -Payload "TWE" `
    -ExpectedMessage "Base64 length is not divisible by four."
Assert-RejectsBase64 `
    -Name "length not divisible by four, MIME wrapped" `
    -Payload "T`r`nWE" `
    -ExpectedMessage "Base64 length is not divisible by four."
Assert-RejectsBase64 `
    -Name "empty input" `
    -Payload "" `
    -ExpectedMessage "Base64 content is empty."
Assert-RejectsBase64 `
    -Name "whitespace-only input" `
    -Payload "`r`n`t " `
    -ExpectedMessage "Base64 content is empty."

# The first '=' is the last raw character of one scan block and the second
# starts the next block. This proves padding state survives block boundaries
# without normalising the full payload into a second string.
$boundaryPayload = "`n" + ("A" * ($ExportScanBlockChars - 2)) + "=="
Assert-AcceptsBase64 `
    -Name "padding split across scan blocks" `
    -Payload $boundaryPayload `
    -ExpectedDecodedSize 196606

Write-Output "Base64 validation contract passed."

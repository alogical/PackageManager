# ASCII (Line Feed -- Newline)
Set-Variable -Name LF -Option Constant -Value ([char]0xA)
Set-Variable -Name CR -Option Constant -Value ([char]0xD)

Set-Variable -Name HEADER_DELIMITER      -Option Constant -Value $LF
Set-Variable -Name HEADER_RFC_TERMINATOR -Option Constant -Value ($CR,$LF,$CR,$LF -join '')

<#
.SYNOPSIS
    Tests client's request header for correctness
#>
function Test-ClientHttpHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]
            $header
        )

    $request = $header.Split($HEADER_DELIMITER)[0]
    $parts   = $request.Split($HEADER_DELIMITER)

    ## Minimum of 3 words in request
    #-- invalid --
    if ($parts.Count -lt 3) {
        return $false
    }
    else {
        return $true
    }
}

<#
.SYNOPSIS
    Test server's response header for correctness
#>
function Test-ServerHttpHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]
            $header
        )

    $response = $header.Split($HEADER_DELIMITER)[0]
    $parts    = $response.Split($HEADER_DELIMITER)

    ## Minimum of 2 words in response
    #-- invalid --
    if ($parts.Count -lt 2) {
        return $false
    }
    else {
        return $true
    }
}

<#
.SYNOPSIS
    Strips newline characters from the start of a buffer.
#>

<#
.SYNOPSIS
    Extract http header from mesage buffer
#>
function Extract-HttpHeader {
    param(
        [Parameter(Mandatory = $true)]
        [Byte[]]
            $buffer
        )

    # Strip leading newlines
    $clone = $buffer
}


/*
    Suspicious JS
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately edtect suspicious calls in JavaScript code.
*/

rule javascript_execcommand {
  meta:
    description = "Detects execCommand calls in Javascript often used for malicious purposes."
    author = "dennist-an"
    reference = "Malware Research"
    date = "2025-01-27"
  strings:
    $x1 = "execCommand"
  condition:
    $x1
}

rule javascript_fingerprint {
  meta:
    description = "Fingerprint2 library is commonly used by tech companies for legitimate purposes; however, it also has the capability to leak browser parameters and can potentially be misused for malicious purposes.."
    author = "dennist-an"
    reference = "Malware Research"
    date = "2025-01-27"
  strings:
    $x1 = "Fingerprintjs2"
    $x2 = "x64hash128"
  condition:
    $x1 or $x2
}

/*
rule javascript_fromCharCode_obfuscation { // known to produce false positives for JS libraries
  meta:
    description = "Detects conversion of char code into string often used in obfuscated JavaScript."
    author = "dennist-an"
    reference = "Malware Research"
    date = "2025-01-27"
  strings:
    $x1 = /\.fromCharCode\(([^)]+)\)/
  condition:
    $x1
}
*/

rule javascript_excessive_hexadecimals {
  meta:
    description = "Detects 10 consecutive hexadecimal escape sequences often used in obfuscated JavaScript."
    author = "dennist-an"
    reference = "Malware Research"
    date = "2025-01-27"
  strings:
    $x1 = /(\\x[0-9a-fA-F]{2}){10,}/
  condition:
    $x1
}

rule webRequest_onBeforeRequest_addListener {
  meta:
    description = "Detects for interception of web requests."
    author = "dennist-an"
    reference = "Malware Research"
    date = "2025-01-27"
  strings:
    $x1 = "webRequest.onBeforeRequest.addListener"
    $x2 = "webRequest.onHeadersReceived.addListener"
    $x3 = "webRequest.onResponseStarted.addListener"
  condition:
    any of ($x1, $x2, $x3)
}

rule javascript_keypress {
  meta:
    description = "Detects JavaScript in extension waiting for document.onkyepress and get.keyCode used in keylogging."
    author = "dennist-an"
    reference = "Malware Research"
    date = "2025-01-27"
  strings:
    $x1 = "document.onkeypress"
    $x2 = "get.keyCode"
  condition:
    any of ($x1, $x2)
}

/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule obfuscated_variables {
  meta:
    description = "Detects for suspicious variable name starting with var _0x"
    author = "dennist-an"
    reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/digging-deep-into-magecart-malware/"
    date = "2025-03-11"
  strings:
    $x1 = /var\s+_0x[a-fA-F0-9]+\s*=\s*\[\s*['"][^'"]*['"](\s*,\s*['"][^'"]*['"])*\s*\]/ nocase
  condition:
    $x1
}

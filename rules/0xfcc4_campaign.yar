/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule xfcc4_campaign {
  meta:
    description = "Detects malware campaign."
    author = "dennist-an"
    reference = "https://unit42.paloaltonetworks.com/malicious-javascript-injection/"
    date = "2025-03-10"
  strings:
    $s1 = "var _0xfcc4"
  condition:
    $s1
}

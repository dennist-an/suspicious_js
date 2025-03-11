/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule fromCharCode {
  meta:
    description = "Detects String.fromCharCode"
    author = "dennist-an"
    reference = "https://unit42.paloaltonetworks.com/malicious-javascript-injection/"
    date = "2025-03-10"
  strings:
    $s1 = "createElement(String.fromCharCode("
  condition:
    $s1
}

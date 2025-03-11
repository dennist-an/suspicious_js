/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule exfiltration_t1 {
  meta:
    description = "Detects for javascript exfiltration techniques using document.write and unescape, following by URL encoded string."
    author = "dennist-an"
    reference = "https://unit42.paloaltonetworks.com/malicious-javascript-steals-sensitive-data/"
    date = "2025-03-10"
  strings:
    $x1 = /document\.write\([a-zA-Z0-9]+\('(%[0-9a-fA-F]{2})+'\)\)/ nocase
  condition:
    $x1
}

/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule exfiltration_t2 {
  meta:
    description = "Detects for javascript exfiltration techniques using telegram bot api."
    author = "dennist-an"
    reference = "https://unit42.paloaltonetworks.com/malicious-javascript-steals-sensitive-data/"
    date = "2025-03-11"
  strings:
    $x1 = "https://api.telegram.org/bot${" nocase
    $x2 = "https://api.telegram.org/file/bot${" nocase
  condition:
    $x1 or $x2
}

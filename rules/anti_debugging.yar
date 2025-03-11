/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule anti_debugging {
  meta:
    description = "Detects for anti debugging techniques"
    author = "dennist-an"
    reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/digging-deep-into-magecart-malware/"
    date = "2025-03-11"
  strings:
    $x1 = "window[\"Firebug\"]"
    $x2 = "window[\"Firebug\"][\"chrome\"]"
    $x3 = "window[\"Firebug\"][\"chrome\"][\"isInitialized\"]"
  condition:
    any of them
}

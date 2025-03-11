/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule suspicious_strings {
  meta:
    description = "Detects for encoded javascript strings that are often used in malicious scenarios."
    author = "dennist-an"
    reference = "https://blog.sucuri.net/2025/02/google-tag-manager-skimmer-steals-credit-card-info-from-magento-site.html"
    date = "2025-03-11"
  strings:
    $x1 = "d2luZG93Lnd3ID0gbmV3IFdlYlNvY2tldCg" /*window.ww = new WebSocket(*/
  condition:
    $x1
}

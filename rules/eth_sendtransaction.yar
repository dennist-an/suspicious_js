/*
    Suspicious JS Rules
    The rules outlined here are intended exclusively for malware investigation purposes
    and are not designed to accurately detect suspicious calls in JavaScript code.
*/

rule ethereum_send_transaction {
    meta:
        description = "Detects for - 'Creates new message call transaction or a contract creation.'"
        author = "dennist-an"
        date = "2025-03-10"
        version = "1.0"
    strings:
        $s1 = "eth_sendTransaction"
    condition:
        $s1
}

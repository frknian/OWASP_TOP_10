# Burp Suite Evidence — 02-conditional-backdoor-bybit-style

This directory contains manual verification screenshots captured using Burp Suite Proxy/Repeater.

## Screenshots List:
* `01-authentication-request.png`: Login request (if applicable).
* `02-vulnerable-request.png`: Exploit payload request sent to the vulnerable port.
* `03-vulnerable-response.png`: Compromised response showing successful exploit.
* `04-fixed-request.png`: Exploit payload request sent to the fixed port.
* `05-fixed-response.png`: Clean/blocked response showing successful defense.

Refer to the central [BURP_EVIDENCE_GUIDE.md](../../../docs/BURP_EVIDENCE_GUIDE.md) for capture and masking guidelines.

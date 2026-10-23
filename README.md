<img width="1536" height="460" alt="Designer" src="https://github.com/user-attachments/assets/f751259a-0f2b-4e09-819f-bd6064847c2d" />


PS4 WebKitty V2 Offline Jailbreak Server ESP32 S3

An offline PS4 jailbreak host based on ArabPixel/WebKitty, ported to the ESP32-S3 platform for a portable and self-contained jailbreak solution.

Supports a wide range of PlayStation 4 firmware versions without requiring an internet connection.

WebKitty


A modular collection of WebKit-based exploit chains for the PlayStation 4. (Formerly known as PSFree Enhanced)

Features Core Exploit & Execution Auto-detection: Automatically detects console type and firmware version. WebKit Exploits: Entry point via the console's web browser using PSFree, Bad Hoist, CSSFontFace or slopkit. Kernel Exploits: Escalates privileges to kernel level using Lapse, Netctrl, or Sleirsgoevy's 6.7x. Payload Loader: After successful kernel exploitation, payloads or listens for incoming payloads on port 9020. Barebone Jailbreak Experience option: Executes the exploit in a minimal DOM footprint and automatically redirects back to the main page upon completion. Firmware-Based Caching: Caches only what your specific firmware version requires instead of caching everything offline. Interface & Customization Themes & Layouts: Customizable layout modes with independent theme options. HEN Flavor Selector: Toggle between HEN and GoldHEN, with integrated GoldHEN version selection. Descriptive Payload Selection: Clear descriptions and unsupported payload loading protection. Multilingual Support: Dynamic language switcher.


Supported PS4 Firmware
<img width="852" height="419" alt="Screenshot 2026-09-07 093714" src="https://github.com/user-attachments/assets/9e026e91-1bdb-421b-8dee-2294319445c1" />

https://youtu.be/-trfe6O2AJQ

Supported ESP32 S3 Boards

Should Work As-Is

✅ LilyGO T-Display S3 (16MB Flash / 8MB PSRAM)

ESP32-S3
16MB Flash
8MB PSRAM
Only caveat is the onboard display. The code doesn't use it, so it simply sits unused.

✅ ESP32-S3 DevKitC-1 N16R8

Almost a direct match to MON16R8
16MB Flash
8MB PSRAM
Probably the safest alternative target.

✅ Waveshare ESP32-S3 N16R8

Same memory configuration
LittleFS and Wi-Fi code should work unchanged.

✅ WeAct Studio ESP32-S3 N16R8

Should run exactly like the MON16R8.

⚠ Region Compatibility Notice:

The update adds universal region support, allowing the firmware to correctly handle different regional document paths so the User Guide loads as expected across all consoles.

Go here to flash it via Web Flasher: https://vegueta-1.github.io/PS4-WebKitty-V2-Offline-Jailbreak-Server-ESP32-S3/

How to use it:

- Go to Settings → Network → Set Up Internet Connection → Use Wi-Fi → Custom if not it will give you an error Connect the PS4 to ESP32-S3 Exploit-PS4 →Password is→ password→ IP Adress Settings- Automatic→ DHCP Host Name- Do Not Specify→ DNS Settings- Automatic→ MTU Settings- Automatic→ Proxy Server- Do Not Use.

-Test Connection

- Do not open the Internet Browser.

- Go to Settings → User's Guide / Helpful Info → User Guide



Copyright & Authors:
This project is licensed under AGPL‑3.0‑or‑later (see LICENSE).
Part of this repository was created by a group of anonymous contributors. We refer to all anonymous contributors simply as “anonymous.”

The original creator’s repository at https://github.com/ArabPixel/WebKitty is currently ONLINE.

Special thanks to the original creator for their work on this project.




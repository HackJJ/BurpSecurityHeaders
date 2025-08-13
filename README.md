# Security Headers Monitor Burp Extension

## Overview
This Burp Suite extension monitors HTTP responses for the presence of important security headers. It provides a configurable UI, summary table, and export options for CSV and AsciiDoc. The extension is written in Jython and is compatible with Burp Suite Professional and Community editions.

## Features
- Monitors a configurable list of security headers in HTTP responses
- Displays results in a sortable table with color-coded missing headers
- Allows export of results to CSV and AsciiDoc
- No duplicate filtering: every in-scope request is logged
- No external network connections or persistent storage
- All file operations are user-initiated

## Installation
1. Download the extension `.py` file.
2. In Burp Suite, go to Extender → Extensions → Add.
3. Set Extension type to **Python** and select the `.py` file.

## Usage
- The extension adds a new tab: **Security Headers**.
- Configure which headers to monitor in the text field at the top.
- All in-scope HTTP responses are logged and analyzed.
- Use the export buttons to save results as CSV or AsciiDoc.
- Use the Clear button to reset the log.

## BApp Store Submission Checklist
This extension meets all [BApp Store acceptance criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria):
- No duplicate functionality with built-in Burp features
- No dangerous, malicious, or privacy-violating behavior
- No unnecessary network, file, or data access
- All exceptions are handled gracefully
- No unnecessary output, logging, or UI elements
- No persistent storage or background processing
- No external dependencies

## Support
For issues or feature requests, please contact the author or submit an issue on the project repository.

## License
This extension is provided under the MIT License.

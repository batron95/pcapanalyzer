PCAP Analyzer

Overview

This Flask-based PCAP Analyzer allows users to upload PCAP (Packet Capture) files and analyze their network traffic. The script utilizes TShark to extract protocol statistics, IP traffic, and DNS queries, and visualizes the results using Matplotlib.

Features

Upload and analyze PCAP files.

Extract protocol statistics, IP traffic, and DNS queries.

Generate Pie Chart and Bar Chart visualizations for protocol distribution.

Toggle between Pie Chart and Bar Chart using a checkbox.

View IP traffic bar graph with horizontal labels.

Built-in .gitignore prevents PCAP files from being uploaded to GitHub.

Installation

Prerequisites

Ensure you have the following installed:

Python 3.7+

TShark (part of Wireshark) – Install via:

Debian/Ubuntu: sudo apt install tshark

MacOS: brew install wireshark

Windows: Download from Wireshark
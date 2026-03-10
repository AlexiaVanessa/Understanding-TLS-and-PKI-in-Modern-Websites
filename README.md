Automated TLS/PKI Security Analysis Tool Overview
The current project is part of the Introduction to Cryptography and Security course. The main aim is to explore the usage of cryptography in the modern web ecosystem. The analysis is performed by exploring the usage of theoretical cryptography concepts in the real world.

Methodology:
The current project uses a reproducible methodology in data analysis:
Dataset: The analysis is performed on a dataset consisting of 1,000 domains.
Deterministic Generation: The list of domains is generated using a Python script, where the full name of the student is used as a random seed source.
Data Collection: A custom Python script, data_collector.py, is designed to iterate over the list of domains and perform a TLS connection on port 443.
Software Tools:
ssl and socket: These tools are used for establishing connections using the HTTPS protocol.
cryptography: This library is used for parsing the properties of the TLS/SSL connections.
csv: This library is used for storing the results in a structured format.

Key Findings
The statistical analysis of the dataset provided the following findings on the status of web security: 
Reachability RateOut of 1,000 domains, 729 could be successfully reached (72.9%), indicating a high rate of HTTPS deployment.
TLS Version SupportThe data shows a decisive dominance of TLSv1.3 with a rate of 85.0%, whereas the rest of the data (15.0%) is using TLSv1.2.
Public Key Infrastructure:
RSA is the dominant algorithm with a rate of 70.55%, mostly using 2048-bit and 4096-bit key lengths. 
ECDSA has a significant rate of 29.45%, with secp256r1 being the most common configuration among those using ECDSA.

CA Ecosystem and ValidityAutomated Certificate Authorities are dominant in the ecosystem, resulting in a high rate of short-lived certificates (~90 days), with 68.6% of the data using this type of certificate.

Project Structure
The project repository contains the following essential files:
select_domains.py: script for domain generation
data_collector.py: script for data collection related to TLS communication analysis
analyzis.py : script for statistical analysis and plotting of the results
domains.txt: text file containing the 1,000 extracted websites
measurements.csv: the raw data collected for analysis.

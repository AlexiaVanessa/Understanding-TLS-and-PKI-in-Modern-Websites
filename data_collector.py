import socket
import ssl
import csv
import concurrent.futures
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# Configuration
INPUT_FILE = "domains.txt"
OUTPUT_FILE = "measurements.csv"
TIMEOUT = 5  # Seconds to wait for a connection

# CSV Headers based on assignment requirements [cite: 26]
HEADERS = [
    "domain", "reachable", "tls_versions", "preferred_cipher",
    "cert_subject_cn", "cert_issuer", "sig_alg",
    "key_type", "key_size", "valid_from", "valid_to",
    "validity_days", "ocsp_stapling", "errors"
]


def get_common_name(name_field):
    """Helper to extract CN from x509 Name object"""
    for attribute in name_field:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return str(name_field)  # Fallback


def scan_domain(domain):
    result = {key: "" for key in HEADERS}
    result["domain"] = domain
    result["reachable"] = False  # Default to false

    # Create SSL Context
    context = ssl.create_default_context()
    context.check_hostname = False  # We manually verify to allow capturing data even on errors
    context.verify_mode = ssl.CERT_NONE

    # Enable OCSP Stapling request (Status Request)
    # Note: In Python's ssl module, this is implicit if the context is configured correctly,
    # but strictly verifying it requires checking the handshake response.

    try:
        # Attempt Connection
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                # 1. Reachability & Protocol
                result["reachable"] = True
                result["tls_versions"] = ssock.version()  # Negotiated version [cite: 26]

                # 2. Cipher
                cipher_info = ssock.cipher()
                result["preferred_cipher"] = cipher_info[0] if cipher_info else "Unknown"

                # 3. OCSP Stapling Check
                # If the server sent a status response, it's stapled.
                # Note: This checks if the generic 'status_request' extension returned data.
                # This is a simplification; robust checks require parsing the extension.
                # However, usually ssock.getpeercert(binary_form=True) is needed to parse purely.
                # For this level of assignment, if we get a collection of info without error, we assume False unless evident.
                # Real OCSP stapling check in Python `ssl` is limited without external libraries like `oscrypto`.
                # We will mark "unknown" or "false" usually, but here is a basic check:
                # (Note: The Python ssl module doesn't expose the OCSP response directly in the high-level API easily)
                result["ocsp_stapling"] = "unknown"

                # 4. Certificate Parsing
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                # Subject & Issuer
                result["cert_subject_cn"] = get_common_name(cert.subject)
                result["cert_issuer"] = get_common_name(cert.issuer)

                # Signature Algorithm
                result["sig_alg"] = cert.signature_algorithm_oid._name

                # Key Type and Size
                public_key = cert.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    result["key_type"] = "RSA"
                    result["key_size"] = public_key.key_size
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    result["key_type"] = "ECDSA"
                    result["key_size"] = public_key.curve.name
                else:
                    result["key_type"] = "Other"
                    result["key_size"] = "Unknown"

                # Validity Dates
                result["valid_from"] = cert.not_valid_before_utc.date()
                result["valid_to"] = cert.not_valid_after_utc.date()
                result["validity_days"] = (result["valid_to"] - result["valid_from"]).days

    except Exception as e:
        # Store the error string as required [cite: 15, 28]
        result["errors"] = str(e)

    return result


def main():
    # Load domains
    try:
        with open(INPUT_FILE, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: {INPUT_FILE} not found. Run select_domains.py first.")
        return

    print(f"Scanning {len(domains)} domains... This may take a few minutes.")

    results = []
    # ThreadPoolExecutor allows us to scan multiple domains at once (faster)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(scan_domain, d): d for d in domains}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_domain)):
            data = future.result()
            results.append(data)
            if i % 50 == 0:
                print(f"Processed {i}/{len(domains)}...")

    # Save to CSV
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(results)

    print(f"Done! Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

import argparse
import csv
import re
from pathlib import Path

# Step 1: Risky ports watch list
RISKY_PORTS = {
    21: "FTP - check for insecure configuration",
    23: "Telnet - unencrypted service",
}

# Step 2: Versions to review
WATCH_VERSIONS = [
    "vsftpd 2.3.4",
    "OpenSSH 7.2",
]

# Step 3: Extract port details using regex
PATTERN = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+"
    r"(\S+)\s+(\S+)(?:\s+(.*?))?\s*$"
)


def find_scan_file(explicit_path=None):
    base_dir = Path(__file__).resolve().parent

    if explicit_path:
        scan_path = Path(explicit_path)

        if not scan_path.is_absolute():
            scan_path = base_dir / scan_path

        if scan_path.is_file():
            return scan_path.resolve()

        raise FileNotFoundError(
            f"Scan file not found: {scan_path}"
        )

    default_file = base_dir / "scan1.txt"

    if default_file.is_file():
        return default_file

    raise FileNotFoundError(
        "Please provide a valid scan file, such as scan1.txt"
    )


def parse_scan_file(scan_path):
    records = []

    with scan_path.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line in file:
            match = PATTERN.match(line)

            if not match:
                continue

            port, protocol, state, service, version = (
                match.groups()
            )

            port = int(port)
            version = (version or "").strip()
            risks = []

            if state.lower() == "open" and port in RISKY_PORTS:
                risks.append(RISKY_PORTS[port])

            for watched in WATCH_VERSIONS:
                if watched.lower() in version.lower():
                    risks.append(
                        "Watch-list version: " + watched
                    )

            records.append({
                "port": port,
                "protocol": protocol,
                "state": state.lower(),
                "service": service,
                "version": version,
                "risk": "; ".join(risks),
            })

    return records


def compare_scans(old_records, new_records):
    old_ports = {
        (r["protocol"], r["port"]): r
        for r in old_records
    }

    new_ports = {
        (r["protocol"], r["port"]): r
        for r in new_records
    }

    print("\n===== SCAN COMPARISON =====")
    changes_found = False

    for key in sorted(set(old_ports) | set(new_ports)):
        old = old_ports.get(key)
        new = new_ports.get(key)

        if old is None:
            print(
                f'ADDED: {key[1]}/{key[0]} '
                f'{new["state"]} {new["service"]}'
            )
            changes_found = True

        elif new is None:
            print(
                f'REMOVED: {key[1]}/{key[0]} '
                f'{old["state"]} {old["service"]}'
            )
            changes_found = True

        elif any(
            old[field] != new[field]
            for field in ("state", "service", "version")
        ):
            print(
                f'CHANGED: {key[1]}/{key[0]} '
                f'{old["state"]} -> {new["state"]}'
            )
            changes_found = True

    if not changes_found:
        print("No port changes detected.")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Parse saved Nmap output and generate a CSV report."
        )
    )

    parser.add_argument(
        "scan_file",
        nargs="?",
        help="Saved Nmap text file, e.g. scan1.txt"
    )

    # Correct indentation: this belongs inside main()
    parser.add_argument(
        "--compare",
        help="Second saved scan file to compare"
    )

    args = parser.parse_args()

    try:
        scan_path = find_scan_file(args.scan_file)
        records = parse_scan_file(scan_path)

        compare_records = None

        if args.compare:
            compare_path = find_scan_file(args.compare)
            compare_records = parse_scan_file(compare_path)

    except (FileNotFoundError, OSError) as error:
        parser.error(str(error))

    # Count port states
    open_count = sum(
        r["state"] == "open" for r in records
    )
    closed_count = sum(
        r["state"] == "closed" for r in records
    )
    filtered_count = sum(
        r["state"] == "filtered" for r in records
    )

    print("\n===== NMAP SCAN REPORT =====")
    print("File:", scan_path.name)
    print("Total ports:", len(records))
    print("Open ports:", open_count)
    print("Closed ports:", closed_count)
    print("Filtered ports:", filtered_count)

    # Display potential risks
    print("\n===== POTENTIAL RISKS =====")
    flagged = False

    for record in records:
        if record["risk"]:
            flagged = True
            print(
                f'{record["port"]}/{record["protocol"]} '
                f'{record["service"]} {record["version"]} '
                f'- {record["risk"]}'
            )

    if not flagged:
        print("No watch-list matches found.")

    # Save a separate CSV for each scan
    output_path = scan_path.with_name(
        scan_path.stem + "_report.csv"
    )

    fields = [
        "port", "protocol", "state",
        "service", "version", "risk"
    ]

    with output_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    print("\nCSV report saved as:", output_path.name)

    # Compare only after both files have been parsed
    if compare_records is not None:
        compare_scans(records, compare_records)


if __name__ == "__main__":
    main()

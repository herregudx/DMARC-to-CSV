import os
import glob
import csv
import xml.etree.ElementTree as ET
from tabulate import tabulate
from datetime import datetime

def colorize(value):
    value_clean = value.lower()

    if all(part.strip() == "pass" for part in value_clean.split(",")):
        return f"\033[92m{value}\033[0m"  # Green
    elif value_clean == "none":
        return f"\033[93m{value}\033[0m"  # Yellow (normal none)
    elif value_clean == "fail":
        return f"\033[91m{value}\033[0m"  # Red
    elif value_clean == "none-temp":
        return f"\033[96mnone (override)\033[0m"  # Cyan for RFC 6.6.2 override
    elif value_clean == "quarantine":
        return f"\033[38;5;208m{value}\033[0m" # Orange
    elif value_clean == "reject":
        return f"\033[91m{value}\033[0m" # Red
    return value

def domains_align_relaxed(auth_domain, header_from):
    auth_domain = auth_domain.lower()
    header_from = header_from.lower()
    return (auth_domain == header_from or
            header_from.endswith("." + auth_domain) or
            auth_domain.endswith("." + header_from))

def evaluate_dmarc_relaxed(spf_results, dkim_results, header_from):
    # SPF
    for domain, result in spf_results:
        if result.lower() == "pass" and domains_align_relaxed(domain, header_from):
            return "pass"

    # DKIM
    for domain, result in dkim_results:
        if result.lower() == "pass" and domains_align_relaxed(domain, header_from):
            return "pass"

    # Temporary errors
    all_results = [result.lower() for _, result in spf_results + dkim_results]

    if "temperror" in all_results:
        return "none-temp"

    return "fail"


def evaluate_dmarc_strict(spf_results, dkim_results, header_from):
    header_from_clean = header_from.lower()

    # SPF
    for domain, result in spf_results:
        if result.lower() == "pass" and domain.lower() == header_from_clean:
            return "pass"

    # DKIM
    for domain, result in dkim_results:
        if result.lower() == "pass" and domain.lower() == header_from_clean:
            return "pass"

    # Temporary errors
    all_results = [result.lower() for _, result in spf_results + dkim_results]

    if "temperror" in all_results:
        return "none-temp"

    return "fail"


def parse_dmarc_report(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        org_name = root.findtext('./report_metadata/org_name') or "Unknown"
        report_rows = []

        for record in root.findall('.//record'):
            header_from = record.findtext('./identifiers/header_from') or ""
            row_data = {
                'Reporter': org_name,
                'Source IP': record.findtext('./row/source_ip'),
                'Count': record.findtext('./row/count'),
                'Disposition': colorize(record.findtext('./row/policy_evaluated/disposition') or ''),
                'Header From': header_from,
                'SPF Domain': '',
                'SPF': '',
                'DKIM Domain': '',
                'DKIM': ''
            }

            # SPF auth results
            spf_results = []

            for spf in record.findall('./auth_results/spf'):
                domain = spf.findtext('domain') or ''
                result = spf.findtext('result') or ''

                spf_results.append((domain, result))

            row_data['SPF Domain'] = ', '.join(
                domain for domain, _ in spf_results
            )

            row_data['SPF'] = colorize(', '.join(
                result for _, result in spf_results
            )) if spf_results else ''


            # DKIM auth results
            dkim_results = []

            for dkim in record.findall('./auth_results/dkim'):
                domain = dkim.findtext('domain') or ''
                result = dkim.findtext('result') or ''

                dkim_results.append((domain, result))

            row_data['DKIM Domain'] = ', '.join(
                domain for domain, _ in dkim_results
            )

            row_data['DKIM'] = colorize(', '.join(
                result for _, result in dkim_results
            )) if dkim_results else 'none'


            # DMARC relaxed
            dmarc_relaxed_result_plain = evaluate_dmarc_relaxed(
                spf_results,
                dkim_results,
                header_from
            )

            row_data['DMARC Relaxed'] = colorize(dmarc_relaxed_result_plain)


            # DMARC strict
            dmarc_strict_result_plain = evaluate_dmarc_strict(
                spf_results,
                dkim_results,
                header_from
            )

            row_data['DMARC Strict'] = colorize(
                dmarc_strict_result_plain
            )

            report_rows.append(row_data)

        return report_rows

    except Exception as e:
        print(f"Error parsing {xml_file}: {e}")
        return []

def strip_ansi(text):
    # Remove ANSI color codes for clean CSV export and logic checks.
    import re
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def export_to_csv(rows):
    if not rows:
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dmarc_report_{timestamp}.csv"

    clean_rows = [
        {k: strip_ansi(v) if isinstance(v, str) else v for k, v in row.items()}
        for row in rows
    ]
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=clean_rows[0].keys())
        writer.writeheader()
        writer.writerows(clean_rows)
    print(f"\nCSV export saved to: {filename}")

def main():
    folder = "dmarc_reports"  # Location of DMARC RUA XML-reports
    xml_files = glob.glob(os.path.join(folder, "**", "*.xml"), recursive=True)

    if not xml_files:
        print(f"No XML files found in '{folder}/'")
        return

    all_rows = []
    for xml_file in xml_files:
        rows = parse_dmarc_report(xml_file)
        all_rows.extend(rows)

    if all_rows:
        print(tabulate(all_rows, headers="keys", tablefmt="grid"))
        export_to_csv(all_rows)
    else:
        print("No DMARC records found in any XML files.")

if __name__ == "__main__":
    main()

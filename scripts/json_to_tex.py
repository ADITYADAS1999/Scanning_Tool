import json
from pathlib import Path

data = {}
if Path("report.json").exists() and Path("report.json").stat().st_size > 0:
    try:
        with open("report.json") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = {}

summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        sev = vuln.get("Severity", "UNKNOWN")
        if sev in summary:
            summary[sev] += 1

with open("report_content.tex", "w") as f:
    f.write("% Auto-generated vulnerability content\n")
    f.write("\\subsection*{Summary}\n")
    f.write("\\begin{itemize}\n")
    for sev, count in summary.items():
        f.write(f"  \\item {sev}: {count}\n")
    f.write("\\end{itemize}\n\n")

    f.write("\\subsection*{Vulnerability Details}\n")
    if any(summary.values()):  # at least 1 vulnerability
        f.write("\\begin{tabular}{|l|l|l|}\n\\hline\n")
        f.write("Package & Vulnerability & Severity \\\\\n\\hline\n")
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                f.write(f"{vuln['PkgName']} & {vuln['VulnerabilityID']} & {vuln['Severity']} \\\\\n")
        f.write("\\hline\n\\end{tabular}\n")
    else:
        f.write("No vulnerabilities were found in this scan. ✅\n")

import json

with open("report.json") as f:
    data = json.load(f)

summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        sev = vuln.get("Severity", "UNKNOWN")
        if sev in summary:
            summary[sev] += 1

# Write LaTeX content
with open("report_content.tex", "w") as f:
    f.write("\\section*{Summary}\n")
    f.write("\\begin{itemize}\n")
    for sev, count in summary.items():
        f.write(f"  \\item {sev}: {count}\n")
    f.write("\\end{itemize}\n\n")

    f.write("\\section*{Vulnerability Details}\n")
    f.write("\\begin{tabular}{|l|l|l|}\n\\hline\n")
    f.write("Package & Vulnerability & Severity \\\\\n\\hline\n")
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            f.write(f"{vuln['PkgName']} & {vuln['VulnerabilityID']} & {vuln['Severity']} \\\\\n")
    f.write("\\hline\n\\end{tabular}\n")

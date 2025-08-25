import json

with open("report.json") as f:
    data = json.load(f)

summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

# Count severities
for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        sev = vuln.get("Severity", "UNKNOWN")
        if sev in summary:
            summary[sev] += 1

with open("report_content.tex", "w") as f:
    f.write("% Auto-generated vulnerability content\n")
    f.write("\\section*{Summary}\n")
    f.write("\\begin{itemize}\n")
    for sev, count in summary.items():
        f.write(f"  \\item {sev}: {count}\n")
    f.write("\\end{itemize}\n\n")

    f.write("\\section*{Vulnerability Details}\n")
    if any(summary.values()):
        f.write("\\begin{longtable}{|p{3cm}|p{3cm}|p{2cm}|p{6cm}|}\n\\hline\n")
        f.write("Package & Vulnerability ID & Severity & Title \\\\\n\\hline\n")
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                pkg = vuln.get("PkgName") or vuln.get("PkgID") or vuln.get("PkgPath", "N/A")
                vid = vuln.get("VulnerabilityID", "N/A")
                sev = vuln.get("Severity", "N/A")
                title = vuln.get("Title", "No title available").replace("&", "\\&")
                f.write(f"{pkg} & {vid} & {sev} & {title} \\\\\n\\hline\n")
        f.write("\\end{longtable}\n")
    else:
        f.write("No vulnerabilities were found in this scan. ✅\n")

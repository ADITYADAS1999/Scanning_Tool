import json
import re

def latex_escape(text: str) -> str:
    if not text:
        return ""

    # Escape backslashes first to avoid interfering with other escapes
    text = re.sub(r'\\', r'\\textbackslash{}', text)

    # Then escape LaTeX special chars
    replacements = {
        "&": r"\&",
        "%": r"\%",
        "_": r"\_",
        "#": r"\#",
        "{": r"\{",
        "}": r"\}",
        "$": r"\$",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    for key, val in replacements.items():
        text = text.replace(key, val)

    return text


def main():
    # Load JSON scan report
    with open("report.json") as f:
        data = json.load(f)

    # Count vulnerabilities by severity
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN")
            if sev in summary:
                summary[sev] += 1

    # Generate LaTeX content
    with open("report_content.tex", "w") as f:
        f.write("% Auto-generated vulnerability content\n")
        f.write("\\section*{Summary}\n")
        f.write("\\begin{itemize}\n")
        for sev, count in summary.items():
            f.write(f"  \\item {sev}: {count}\n")
        f.write("\\end{itemize}\n\n")

        f.write("\\section*{Vulnerability Details}\n")
        if any(summary.values()):
            f.write(
                "\\begin{longtable}{|p{3cm}|p{2.5cm}|p{2cm}|p{4cm}|p{5cm}|}\n\\hline\n"
            )
            f.write("Package & Vulnerability ID & Severity & Title & Description \\\\\n\\hline\n")

            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    pkg = vuln.get("PkgName") or vuln.get("PkgID") or "N/A"
                    vid = vuln.get("VulnerabilityID", "N/A")
                    sev = vuln.get("Severity", "N/A")
                    title = latex_escape(vuln.get("Title", "No title available"))
                    desc = latex_escape(vuln.get("Description", "No description available"))

                    f.write(f"{pkg} & {vid} & {sev} & {title} & {desc} \\\\\n\\hline\n")

            f.write("\\end{longtable}\n")
        else:
            f.write("No vulnerabilities were found in this scan. ✅\n")


if __name__ == "__main__":
    main()

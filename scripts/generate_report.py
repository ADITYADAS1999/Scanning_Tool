from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import json

def generate_report():
    # Load JSON scan results
    with open("report.json") as f:
        data = json.load(f)

    c = canvas.Canvas("report.pdf", pagesize=A4)
    width, height = A4

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(100, height - 50, "Docker Vulnerability Scan Report")

    c.setFont("Helvetica", 12)
    c.drawString(100, height - 80, "Generated from Trivy JSON results")

    # Summary counts
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN")
            if sev in summary:
                summary[sev] += 1

    y = height - 120
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, y, "Severity Summary:")
    y -= 20
    c.setFont("Helvetica", 12)
    for sev, count in summary.items():
        c.drawString(120, y, f"{sev}: {count}")
        y -= 20

    # Vulnerability details
    y -= 20
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, y, "Vulnerability Details:")
    y -= 20

    c.setFont("Helvetica", 10)
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            pkg = vuln.get("PkgName", "N/A")
            vid = vuln.get("VulnerabilityID", "N/A")
            sev = vuln.get("Severity", "N/A")
            title = vuln.get("Title", "N/A")
            c.drawString(100, y, f"{pkg} | {vid} | {sev} | {title[:60]}")
            y -= 12
            if y < 50:  # page break
                c.showPage()
                y = height - 50

    c.save()

if __name__ == "__main__":
    generate_report()

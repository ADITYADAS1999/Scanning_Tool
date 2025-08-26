from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
)
from reportlab.lib import colors
from pypdf import PdfMerger
from reportlab.lib.styles import getSampleStyleSheet
import matplotlib.pyplot as plt
import json
#from PyPDF2 import PdfMerger


def generate_charts(summary):
    """Generate bar and pie charts for severity summary."""
    severities = list(summary.keys())
    counts = list(summary.values())

    # --- Bar Chart ---
    plt.figure(figsize=(5, 3))
    plt.bar(severities, counts, color=["red", "orange", "gold", "green"])
    plt.title("Vulnerabilities by Severity (Bar Chart)")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("bar_chart.png")
    plt.close()

    # --- Pie Chart ---
    plt.figure(figsize=(4, 4))
    plt.pie(
        counts,
        labels=severities,
        autopct="%1.1f%%",
        colors=["red", "orange", "gold", "green"],
        startangle=140,
    )
    plt.title("Vulnerabilities by Severity (Pie Chart)")
    plt.tight_layout()
    plt.savefig("pie_chart.png")
    plt.close()


def build_report():
    """Generate vulnerability report (without cover page)."""
    # Load JSON scan results
    with open("report.json") as f:
        data = json.load(f)

    doc = SimpleDocTemplate("report.pdf", pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    # Title
    title = Paragraph("<b>Docker Vulnerability Scan Report</b>", styles["Title"])
    subtitle = Paragraph("Generated from Trivy JSON results", styles["Normal"])
    elements.extend([title, subtitle, Spacer(1, 20)])

    # Summary counts
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN")
            if sev in summary:
                summary[sev] += 1

    elements.append(Paragraph("<b>Severity Summary:</b>", styles["Heading2"]))
    for sev, count in summary.items():
        elements.append(Paragraph(f"{sev}: {count}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # Generate and add charts
    generate_charts(summary)
    elements.append(Image("bar_chart.png", width=350, height=200))
    elements.append(Spacer(1, 20))
    elements.append(Image("pie_chart.png", width=300, height=300))
    elements.append(Spacer(1, 30))

    # Vulnerability details table
    elements.append(Paragraph("<b>Vulnerability Details:</b>", styles["Heading2"]))

    table_data = [["Package", "Vulnerability ID", "Severity", "Title"]]
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            pkg = vuln.get("PkgName", "N/A")
            vid = vuln.get("VulnerabilityID", "N/A")
            sev = vuln.get("Severity", "N/A")
            title = vuln.get("Title", "N/A")
            table_data.append([pkg, vid, sev, title])

    table = Table(table_data, colWidths=[100, 120, 60, 200])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cccccc")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    elements.append(table)

    # Build PDF
    doc.build(elements)


def merge_pdfs(front_page, report, output):
    """Merge cover page and report into final PDF."""
    merger = PdfMerger()
    merger.append(front_page)
    merger.append(report)
    merger.write(output)
    merger.close()


if __name__ == "__main__":
    # Step 1: Build vulnerability report
    build_report()

    # Step 2: Merge with front-page template (report_format.pdf)
    merge_pdfs("report_format.pdf", "report.pdf", "final_report.pdf")
    print("✅ Final report generated: final_report.pdf")

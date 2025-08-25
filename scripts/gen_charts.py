import json
import matplotlib.pyplot as plt

with open("report.json") as f:
    data = json.load(f)

summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        sev = vuln.get("Severity", "UNKNOWN")
        if sev in summary:
            summary[sev] += 1

# Pie chart
labels = list(summary.keys())
sizes = list(summary.values())
colors = ['#d73027','#fc8d59','#fee08b','#91cf60']

plt.figure(figsize=(5,5))
plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
plt.title("Vulnerability Severity Distribution")
plt.savefig("assets/severity_chart.png")

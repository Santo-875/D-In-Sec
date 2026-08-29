from fpdf import FPDF

pdf = FPDF()
pdf.add_page()
pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "ORBITAL SHIELD SECURITY OPERATIONS", ln=True, align="C")
pdf.cell(0, 10, "CONFIDENTIAL INCIDENT REPORT", ln=True, align="C")
pdf.ln(10)

pdf.set_font("Helvetica", "B", 14)
pdf.cell(0, 10, "1. Executive Summary", ln=True)
pdf.set_font("Helvetica", "", 11)
pdf.multi_cell(0, 5, "On 2026-08-25 at 12:04:35 UTC, the monitoring system detected...")
pdf.ln(5)

pdf.set_font("Helvetica", "B", 14)
pdf.cell(0, 10, "2. Incident Specifications", ln=True)
pdf.set_font("Helvetica", "B", 11)
pdf.set_fill_color(30, 40, 60)
pdf.set_text_color(255, 255, 255)
pdf.cell(95, 8, "Attribute", border=1, fill=True)
pdf.cell(95, 8, "Value", border=1, fill=True, ln=True)

pdf.set_font("Helvetica", "", 11)
pdf.set_text_color(0, 0, 0)
pdf.cell(95, 8, "Incident ID", border=1)
pdf.cell(95, 8, "EVT-2130", border=1, ln=True)
pdf.cell(95, 8, "Target Satellite", border=1)
pdf.cell(95, 8, "N/A", border=1, ln=True)

pdf_bytes = pdf.output()
print("Success. Byte length:", len(pdf_bytes))

from fpdf import FPDF

try:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    
    safe_text = "Test PDF text"
    
    pdf.multi_cell(0, 6, text=safe_text)
    pdf_bytes = pdf.output()
    print(type(pdf_bytes))
    print("PDF generation success")
except Exception as e:
    print(f"Error: {e}")

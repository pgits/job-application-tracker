import os
import sys
from datetime import datetime

def check_pdf_requirements():
    """Check if PDF generation requirements are met"""
    print("🔍 Checking PDF Generation Requirements...")
    print("=" * 50)
    
    # Check if reportlab is installed
    try:
        import reportlab
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        print("✅ ReportLab is installed and importable")
        print(f"   Version: {reportlab.Version}")
    except ImportError as e:
        print("❌ ReportLab is NOT installed")
        print(f"   Error: {e}")
        print("   Install with: pip install reportlab")
        return False
    except Exception as e:
        print(f"❌ ReportLab import error: {e}")
        return False
    
    # Check data directory
    data_dir = "./data"
    if not os.path.exists(data_dir):
        print(f"📁 Creating data directory: {data_dir}")
        os.makedirs(data_dir)
    else:
        print(f"✅ Data directory exists: {data_dir}")
    
    # Check write permissions
    try:
        test_file = os.path.join(data_dir, "test_write.txt")
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        print("✅ Write permissions OK in data directory")
    except Exception as e:
        print(f"❌ Cannot write to data directory: {e}")
        return False
    
    return True

def test_simple_pdf():
    """Create a simple test PDF to verify functionality"""
    print("\n🧪 Testing Simple PDF Creation...")
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        
        filename = "data/test_pdf.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        
        story = [
            Paragraph("Test PDF Generation", styles['Title']),
            Paragraph("If you can see this, PDF generation is working!", styles['Normal'])
        ]
        
        doc.build(story)
        
        if os.path.exists(filename):
            print(f"✅ Test PDF created successfully: {filename}")
            print(f"   File size: {os.path.getsize(filename)} bytes")
            return True
        else:
            print("❌ Test PDF was not created")
            return False
            
    except Exception as e:
        print(f"❌ Error creating test PDF: {e}")
        return False

def check_existing_files():
    """Check what files exist in the data directory"""
    print("\n📁 Checking Existing Files in ./data...")
    
    data_dir = "./data"
    if not os.path.exists(data_dir):
        print("❌ Data directory doesn't exist")
        return
    
    files = os.listdir(data_dir)
    if not files:
        print("📂 Data directory is empty")
        return
    
    print(f"📄 Found {len(files)} files:")
    for file in sorted(files):
        file_path = os.path.join(data_dir, file)
        size = os.path.getsize(file_path)
        mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
        print(f"   {file} ({size} bytes, modified: {mod_time.strftime('%Y-%m-%d %H:%M:%S')})")

def debug_job_tracker():
    """Debug the job tracker to see why PDF isn't generated"""
    print("\n🔧 Debugging Job Tracker PDF Generation...")
    
    # Check if we can import the job tracker
    try:
        # This assumes your job tracker is in the same directory
        import job_tracker
        print("✅ Job tracker module imported successfully")
    except ImportError as e:
        print(f"❌ Cannot import job tracker: {e}")
        return
    except Exception as e:
        print(f"❌ Error importing job tracker: {e}")
        return
    
    # Create a tracker instance and check its PDF method
    try:
        tracker = job_tracker.JobApplicationTracker()
        
        # Check if the PDF method exists
        if hasattr(tracker, 'generate_nc_unemployment_pdf'):
            print("✅ PDF generation method exists in tracker")
        else:
            print("❌ PDF generation method NOT found in tracker")
            return
        
        # Check if REPORTLAB_AVAILABLE is set correctly
        if hasattr(job_tracker, 'REPORTLAB_AVAILABLE'):
            print(f"📊 REPORTLAB_AVAILABLE = {job_tracker.REPORTLAB_AVAILABLE}")
            if not job_tracker.REPORTLAB_AVAILABLE:
                print("❌ ReportLab marked as unavailable in job tracker")
                print("   This is why PDF generation is being skipped")
        
    except Exception as e:
        print(f"❌ Error checking job tracker: {e}")

def create_sample_nc_pdf():
    """Create a sample NC unemployment PDF with dummy data"""
    print("\n📋 Creating Sample NC Unemployment PDF...")
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        
        filename = "data/Sample_NC_Unemployment_Report.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter, 
                               topMargin=0.5*inch, bottomMargin=0.5*inch,
                               leftMargin=0.5*inch, rightMargin=0.5*inch)
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=14,
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Build the document
        story = []
        
        # Header
        story.append(Paragraph("North Carolina Department of Commerce", title_style))
        story.append(Paragraph("Division of Employment Security", subtitle_style))
        story.append(Paragraph("Unemployment Insurance", subtitle_style))
        story.append(Spacer(1, 20))
        
        # Week header
        week_header = "Week #1 Beginning Sunday (Date): 03/27/2025 Ending Saturday (Date): 04/02/2025"
        story.append(Paragraph(week_header, styles['Heading2']))
        story.append(Spacer(1, 10))
        
        # Sample table data
        table_data = [
            ["1. Date of\nContact or\nActivity\n03/28/2025", "Company or Activity:\nMicrosoft", "Contact Name:\nSarah Johnson", "Result:\nNo Response"],
            ["", "Position Sought:\nSoftware Engineer", "Contact Method:\nEmail", ""],
            ["", "", "Contact Information:\nsarah.johnson@microsoft.com", ""],
            ["", "", "", ""],
            ["2. Date of\nContact or\nActivity\n03/29/2025", "Company or Activity:\nGoogle", "Contact Name:\nLinkedIn", "Result:\nRejection"],
            ["", "Position Sought:\nFull Stack Developer", "Contact Method:\nLinkedIn", ""],
            ["", "", "Contact Information:\nLinkedIn Profile", ""]
        ]
        
        # Create and style the table
        table = Table(table_data, colWidths=[1.2*inch, 2.8*inch, 2.2*inch, 1.3*inch])
        table.setStyle(TableStyle([
            # Borders
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            
            # Header styling
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            
            # Alignment
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            
            # Background colors for better readability
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ]))
        
        story.append(table)
        
        # Build PDF
        doc.build(story)
        
        if os.path.exists(filename):
            print(f"✅ Sample NC PDF created: {filename}")
            print(f"   File size: {os.path.getsize(filename)} bytes")
            return True
        else:
            print("❌ Sample PDF was not created")
            return False
            
    except Exception as e:
        print(f"❌ Error creating sample PDF: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all diagnostic checks"""
    print("🔍 NC Unemployment PDF Generation Diagnostics")
    print("=" * 60)
    
    # Check requirements
    if not check_pdf_requirements():
        print("\n❌ Requirements not met. Please install ReportLab and try again.")
        return
    
    # Test simple PDF
    if not test_simple_pdf():
        print("\n❌ Basic PDF generation failed. Check your ReportLab installation.")
        return
    
    # Check existing files
    check_existing_files()
    
    # Debug job tracker
    debug_job_tracker()
    
    # Create sample PDF
    if create_sample_nc_pdf():
        print("\n🎉 Sample NC unemployment PDF created successfully!")
        print("This proves PDF generation is working.")
        print("\nIf your job tracker isn't creating PDFs, the issue is likely:")
        print("1. No outbound applications found in your data")
        print("2. REPORTLAB_AVAILABLE flag is False in job tracker")
        print("3. An error in the PDF generation logic")
    
    print("\n📋 Next Steps:")
    print("1. Run this diagnostic script to verify everything works")
    print("2. Check if you have outbound applications in your data")
    print("3. Look for error messages when running the job tracker")
    print("4. Verify the REPORTLAB_AVAILABLE flag in your job tracker")

if __name__ == "__main__":
    main()

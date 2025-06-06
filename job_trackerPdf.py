import pickle
import os
import csv
import re
from datetime import datetime, timedelta
from collections import defaultdict
import base64
import email
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pandas as pd

# Add PDF generation capability
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
    print("✅ ReportLab loaded - PDF generation available")
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠️  ReportLab not installed. PDF generation will be skipped.")
    print("Install with: pip install reportlab")

# Configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
ACCOUNTS = [
    'pgits.job@gmail.com',
    'pgits.geekgaps@gmail.com', 
    'petergits@gmail.com'
]

START_DATE = '2025/03/27'  # March 27, 2025

class JobApplicationTracker:
    def __init__(self):
        self.services = {}
        self.job_applications = []
        self.weekly_data = {}
        
    def load_authenticated_services(self):
        """Load previously authenticated Gmail services"""
        print("🔄 Loading authenticated Gmail services...")
        
        for account in ACCOUNTS:
            token_file = f'tokens/token_{account.replace("@", "_").replace(".", "_")}.pickle'
            
            if not os.path.exists(token_file):
                print(f"❌ No token found for {account}")
                print("Please run authenticate_accounts.py first!")
                return False
                
            try:
                with open(token_file, 'rb') as token:
                    creds = pickle.load(token)
                
                # Refresh if needed
                if creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                
                service = build('gmail', 'v1', credentials=creds)
                self.services[account] = service
                print(f"✅ Loaded service for {account}")
                
            except Exception as e:
                print(f"❌ Error loading {account}: {e}")
                return False
        
        return True
    
    def extract_company_from_email(self, email_address, email_content=""):
        """Extract company name from email address or content"""
        if not email_address:
            return "Unknown"
            
        # Common patterns to remove
        domain = email_address.split('@')[-1].lower()
        
        # Skip common email providers
        common_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 
                          'aol.com', 'icloud.com', 'live.com']
        
        if domain in common_providers:
            return "LinkedIn"
        
        # Extract company name from domain
        company_parts = domain.replace('.com', '').replace('.org', '').replace('.net', '')
        company_parts = company_parts.split('.')
        
        # Take the main domain part
        company_name = company_parts[0] if company_parts else "Unknown"
        
        # Capitalize first letter
        company_name = company_name.capitalize()
        
        # Handle special cases
        company_mappings = {
            'microsoft': 'Microsoft',
            'google': 'Google', 
            'amazon': 'Amazon',
            'meta': 'Meta',
            'apple': 'Apple',
            'linkedin': 'LinkedIn',
            'glassdoor': 'Glassdoor'
        }
        
        return company_mappings.get(company_name.lower(), company_name)
    
    def extract_position_from_content(self, subject, body):
        """Extract job position from email subject and body"""
        # Common position keywords to look for
        position_patterns = [
            # Direct position mentions
            r'(?:position|role|job|opening):\s*([^,\n\.]+)',
            r'(?:for|as)\s+(?:a\s+|an\s+)?([^,\n\.]+?)\s+(?:position|role|at|with)',
            # Subject line patterns
            r'(?:software|senior|junior|lead|principal|staff)\s+(?:engineer|developer|programmer|analyst)',
            r'(?:data|machine learning|ml|ai)\s+(?:scientist|engineer|analyst)',
            r'(?:product|project|program)\s+manager',
            r'(?:full stack|frontend|backend|front end|back end)\s+(?:engineer|developer)',
            r'(?:devops|site reliability|sre)\s+engineer',
            r'(?:qa|quality assurance)\s+(?:engineer|analyst|tester)',
            r'(?:business|systems|security)\s+analyst',
            r'(?:technical|solution|enterprise)\s+architect',
            r'(?:ui|ux|user experience|user interface)\s+(?:designer|engineer)',
        ]
        
        # Combine subject and first part of body for analysis
        text_to_search = (subject + " " + body[:500]).lower()
        
        # Try to find position mentions
        for pattern in position_patterns:
            matches = re.findall(pattern, text_to_search, re.IGNORECASE)
            if matches:
                # Clean up the match
                position = matches[0].strip()
                # Remove common unnecessary words
                position = re.sub(r'\b(the|a|an|this|that|our|your)\b', '', position, flags=re.IGNORECASE)
                position = position.strip()
                
                # Capitalize properly
                if position:
                    return ' '.join(word.capitalize() for word in position.split())
        
        # Look for position in subject line more broadly
        subject_lower = subject.lower()
        common_positions = [
            'software engineer', 'senior software engineer', 'junior software engineer',
            'full stack developer', 'frontend developer', 'backend developer',
            'data scientist', 'data engineer', 'data analyst',
            'product manager', 'project manager', 'program manager',
            'devops engineer', 'site reliability engineer', 'sre',
            'qa engineer', 'quality assurance engineer',
            'business analyst', 'systems analyst', 'security analyst',
            'technical architect', 'solution architect',
            'ui designer', 'ux designer', 'user experience designer'
        ]
        
        for position in common_positions:
            if position in subject_lower:
                return ' '.join(word.capitalize() for word in position.split())
        
        return "Not Specified"
    
    def extract_physical_address(self, body, signature_text=""):
        """Extract physical address from email body"""
        # Common address patterns
        address_patterns = [
            # Full address with state and zip
            r'(\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Circle|Cir|Court|Ct|Place|Pl)\s*,?\s*[A-Za-z\s]+,\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?)',
            # City, State ZIP
            r'([A-Za-z\s]+,\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?)',
            # Address with just state abbreviation
            r'(\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way)\s*,?\s*[A-Za-z\s]+,\s*[A-Z]{2})',
        ]
        
        # Look in signature first (usually more reliable)
        text_to_search = signature_text + " " + body
        
        # Remove HTML tags if present
        text_to_search = re.sub(r'<[^>]+>', ' ', text_to_search)
        
        for pattern in address_patterns:
            matches = re.findall(pattern, text_to_search, re.MULTILINE)
            if matches:
                # Return the first valid-looking address
                for match in matches:
                    address = match.strip()
                    # Basic validation - should have at least a number and a state
                    if re.search(r'\d', address) and re.search(r'[A-Z]{2}', address):
                        return address
        
        # Look for just city, state (without full address)
        city_state_pattern = r'\b([A-Za-z\s]+),\s*([A-Z]{2})\b'
        matches = re.findall(city_state_pattern, text_to_search)
        if matches:
            for city, state in matches:
                # Filter out common false positives
                if len(city.strip()) > 2 and city.strip().lower() not in [
                    'best regards', 'thank you', 'sincerely', 'yours truly', 'kind regards'
                ]:
                    return f"{city.strip()}, {state}"
        
        return ""
    
    def extract_hr_contact(self, sender_name, sender_email):
        """Extract HR contact name"""
        if not sender_name or sender_name.strip() == "":
            return "LinkedIn"
        
        # Clean up sender name
        name = sender_name.strip()
        
        # Remove email addresses from name if present
        name = re.sub(r'<.*?>', '', name).strip()
        
        # If it's just an email or no-reply, use LinkedIn
        if 'noreply' in name.lower() or 'no-reply' in name.lower() or '@' in name:
            return "LinkedIn"
        
        return name if name else "LinkedIn"
    
    def is_rejection_email(self, subject, body):
        """Check if email is a rejection"""
        rejection_keywords = [
            'unfortunately', 'not selected', 'not be moving forward',
            'decided to move forward with other candidates',
            'not advance', 'not proceeding', 'not continue',
            'thank you for your interest', 'will not be moving forward',
            'have decided to', 'chosen to pursue other candidates',
            'position has been filled', 'we have filled the position'
        ]
        
        text_to_check = (subject + " " + body).lower()
        
        for keyword in rejection_keywords:
            if keyword in text_to_check:
                return True
        
        return False
    
    def get_message_content(self, service, message_id):
        """Get full message content"""
        try:
            message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
            
            payload = message['payload']
            headers = payload.get('headers', [])
            
            # Extract headers
            subject = ""
            sender = ""
            sender_email = ""
            date_str = ""
            
            for header in headers:
                name = header['name'].lower()
                value = header['value']
                
                if name == 'subject':
                    subject = value
                elif name == 'from':
                    sender = value
                    # Extract email from "Name <email@domain.com>" format
                    email_match = re.search(r'<(.+?)>', value)
                    if email_match:
                        sender_email = email_match.group(1)
                        sender = value.split('<')[0].strip()
                    else:
                        sender_email = value
                        sender = ""
                elif name == 'date':
                    date_str = value
            
            # Extract body
            body = self.extract_body_from_payload(payload)
            
            return {
                'subject': subject,
                'sender': sender,
                'sender_email': sender_email,
                'date': date_str,
                'body': body,
                'message_id': message_id
            }
            
        except Exception as e:
            print(f"Error getting message content: {e}")
            return None
    
    def extract_body_from_payload(self, payload):
        """Extract email body from message payload"""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                elif part['mimeType'] == 'text/html':
                    data = part['body']['data']
                    html_body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    # Simple HTML to text conversion
                    body += re.sub('<[^<]+?>', '', html_body)
        else:
            if payload['mimeType'] == 'text/plain':
                data = payload['body']['data']
                body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        
        return body
    
    def check_if_corresponded(self, service, sender_email, subject, account_email):
        """Check if I sent a reply or original message to this email/company"""
        try:
            # Extract domain from sender email
            domain = sender_email.split('@')[-1] if '@' in sender_email else ""
            
            # Search for emails I sent to this domain or email
            search_queries = [
                f'to:{sender_email}',  # Direct email to sender
                f'to:*@{domain}' if domain else '',  # Any email to company domain
            ]
            
            for query in search_queries:
                if not query:  # Skip empty queries
                    continue
                    
                try:
                    results = service.users().messages().list(
                        userId='me',
                        q=f'in:sent {query}',
                        maxResults=10
                    ).execute()
                    
                    messages = results.get('messages', [])
                    if messages:
                        return True
                        
                except Exception as e:
                    continue
            
            return False
            
        except Exception as e:
            return False
    
    def should_exclude_message(self, sender_email, subject):
        """Check if message should be excluded from results"""
        # Exclude LinkedIn job alerts
        if 'jobalerts-noreply@linkedin.com' in sender_email.lower():
            return True
        
        # Exclude other automated job alerts that aren't actual applications
        exclude_patterns = [
            'jobalerts',
            'job-alerts', 
            'noreply',
            'no-reply'
        ]
        
        email_lower = sender_email.lower()
        subject_lower = subject.lower()
        
        # Only exclude if it's clearly an automated alert
        if any(pattern in email_lower for pattern in exclude_patterns):
            # But keep if it seems like a real application response
            if not any(keyword in subject_lower for keyword in [
                'thank you for applying', 'application received', 
                'interview', 'unfortunately', 'not selected'
            ]):
                return True
        
        return False
    
    def search_job_related_emails(self, service, account_email):
        """Search for job-related emails in an account"""
        print(f"🔍 Searching {account_email} for job applications...")
        
        # Search queries for different types of job-related emails
        search_queries = [
            f'after:{START_DATE} (subject:application OR subject:applied OR subject:position OR subject:job)',
            f'after:{START_DATE} (subject:interview OR subject:opportunity OR subject:recruiter)',
            f'after:{START_DATE} ("thank you for applying" OR "unfortunately" OR "not selected")',
            f'after:{START_DATE} (from:linkedin OR from:glassdoor)',
            f'after:{START_DATE} (subject:"software engineer" OR subject:"developer" OR subject:"programmer")',
        ]
        
        all_messages = set()  # Use set to avoid duplicates
        
        for query in search_queries:
            try:
                results = service.users().messages().list(
                    userId='me',
                    q=query,
                    maxResults=100
                ).execute()
                
                messages = results.get('messages', [])
                for msg in messages:
                    all_messages.add(msg['id'])
                    
            except Exception as e:
                print(f"  ⚠️  Error with query '{query}': {e}")
                continue
        
        print(f"  📧 Found {len(all_messages)} unique messages")
        
        # Process each message
        applications = []
        for message_id in all_messages:
            content = self.get_message_content(service, message_id)
            if content:
                app_data = self.process_message(content, account_email)
                if app_data:
                    applications.append(app_data)
        
        print(f"  ✅ Processed {len(applications)} job-related emails")
        return applications
    
    def process_message(self, message_content, account_email):
        """Process a message and extract job application data"""
        try:
            # Check if this message should be excluded
            if self.should_exclude_message(message_content['sender_email'], message_content['subject']):
                return None
            
            # Parse date
            date_str = message_content['date']
            try:
                # Parse various date formats
                msg_date = self.parse_email_date(date_str)
            except:
                msg_date = datetime.now()
            
            # Extract company info
            company_name = self.extract_company_from_email(
                message_content['sender_email'], 
                message_content['body']
            )
            
            # Extract position
            position = self.extract_position_from_content(
                message_content['subject'],
                message_content['body']
            )
            
            # Extract HR contact
            hr_contact = self.extract_hr_contact(
                message_content['sender'], 
                message_content['sender_email']
            )
            
            # Extract physical address
            physical_address = self.extract_physical_address(message_content['body'])
            
            # Check if it's a rejection
            is_rejection = self.is_rejection_email(
                message_content['subject'], 
                message_content['body']
            )
            
            # Determine if this is an outbound application or company response
            subject_lower = message_content['subject'].lower()
            is_outbound = any(keyword in subject_lower for keyword in [
                'application', 'applying', 'interested in', 'resume'
            ])
            
            # Check if I corresponded with this company/person
            corresponded = self.check_if_corresponded(
                self.services[account_email],
                message_content['sender_email'],
                message_content['subject'],
                account_email
            )
            
            return {
                'date': msg_date,
                'company_name': company_name,
                'position': position,
                'hr_contact': hr_contact,
                'company_email': message_content['sender_email'],
                'subject': message_content['subject'],
                'is_rejection': is_rejection,
                'is_outbound': is_outbound,
                'corresponded': corresponded,
                'physical_address': physical_address,
                'account': account_email,
                'message_id': message_content['message_id']
            }
            
        except Exception as e:
            print(f"  ⚠️  Error processing message: {e}")
            return None
    
    def parse_email_date(self, date_str):
        """Parse email date string"""
        try:
            # Remove timezone info for simpler parsing
            date_str = re.sub(r'\s*\([^)]+\)', '', date_str)
            date_str = re.sub(r'\s*[+-]\d{4}', '', date_str)
            
            # Try different date formats
            formats = [
                '%a, %d %b %Y %H:%M:%S',
                '%d %b %Y %H:%M:%S',
                '%Y-%m-%d %H:%M:%S',
                '%a, %d %b %Y',
                '%d %b %Y'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_str.strip(), fmt)
                except:
                    continue
            
            # If all else fails, return current date
            return datetime.now()
            
        except:
            return datetime.now()
    
    def organize_by_week(self, applications):
        """Organize applications by week"""
        weekly_data = defaultdict(list)
        
        # Start from March 27, 2025
        start_date = datetime(2025, 3, 27)
        
        for app in applications:
            # Calculate week
            days_diff = (app['date'] - start_date).days
            week_num = days_diff // 7
            week_start = start_date + timedelta(weeks=week_num)
            week_key = week_start.strftime("Week of %m/%d/%Y")
            
            weekly_data[week_key].append(app)
        
        return dict(weekly_data)
    
    def filter_outbound_applications(self, applications):
        """Filter to only outbound applications for NC unemployment report"""
        outbound_apps = []
        
        for app in applications:
            # Check if this is an outbound application
            if app.get('is_outbound', False):
                outbound_apps.append(app)
            # Also include applications where we corresponded (likely outbound)
            elif app.get('corresponded', False):
                outbound_apps.append(app)
            # Include applications with specific subjects that indicate we applied
            elif any(keyword in app.get('subject', '').lower() for keyword in [
                'thank you for applying', 'application received', 'we have received your application'
            ]):
                outbound_apps.append(app)
        
        return outbound_apps
    
    def generate_csv_report(self, weekly_data):
        """Generate main CSV report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data/Job_Application_History_NC_{timestamp}.csv"
        
        # Ensure data directory exists
        os.makedirs('data', exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Week', 'Company_Name', 'Position', 'HR_Contact', 'Company_Email', 
                'Application_Date', 'Corresponded', 'Rejection_Status', 'Rejection_Date', 'Notes', 'Physical_Address'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Sort weeks chronologically
            sorted_weeks = sorted(weekly_data.keys(), 
                                key=lambda x: datetime.strptime(x.replace('Week of ', ''), '%m/%d/%Y'))
            
            for week in sorted_weeks:
                applications = weekly_data[week]
                
                for app in applications:
                    # Determine rejection info
                    rejection_status = "Rejected" if app['is_rejection'] else "No Response"
                    rejection_date = app['date'].strftime('%m/%d/%Y') if app['is_rejection'] else ""
                    
                    # Create notes
                    notes = f"Subject: {app['subject'][:50]}..."
                    if app['is_outbound']:
                        notes += " [Outbound Application]"
                    
                    writer.writerow({
                        'Week': week,
                        'Company_Name': app['company_name'],
                        'Position': app['position'],
                        'HR_Contact': app['hr_contact'],
                        'Company_Email': app['company_email'],
                        'Application_Date': app['date'].strftime('%m/%d/%Y'),
                        'Corresponded': 'Yes' if app['corresponded'] else 'No',
                        'Rejection_Status': rejection_status,
                        'Rejection_Date': rejection_date,
                        'Notes': notes,
                        'Physical_Address': app['physical_address']
                    })
        
        print(f"📄 Main CSV report generated: {filename}")
        return filename
    
    def generate_nc_unemployment_csv(self, weekly_data):
        """Generate NC unemployment CSV report (outbound applications only)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data/NC_Unemployment_Report_{timestamp}.csv"
        
        # Ensure data directory exists
        os.makedirs('data', exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Week', 'Company_Name', 'Position', 'HR_Contact', 'Company_Email', 
                'Application_Date', 'Contact_Method', 'Contact_Information', 'Result', 'Physical_Address'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Sort weeks chronologically
            sorted_weeks = sorted(weekly_data.keys(), 
                                key=lambda x: datetime.strptime(x.replace('Week of ', ''), '%m/%d/%Y'))
            
            for week in sorted_weeks:
                applications = weekly_data[week]
                outbound_apps = self.filter_outbound_applications(applications)
                
                for app in outbound_apps:
                    # Determine contact method
                    contact_method = "Email" if app['company_email'] else "LinkedIn"
                    
                    # Determine result
                    if app['is_rejection']:
                        result = "Rejection"
                    elif app['corresponded']:
                        result = "Response Received"
                    else:
                        result = "No Response"
                    
                    # Contact information
                    contact_info = app['company_email'] if app['company_email'] else "LinkedIn Profile"
                    
                    writer.writerow({
                        'Week': week,
                        'Company_Name': app['company_name'],
                        'Position': app['position'],
                        'HR_Contact': app['hr_contact'],
                        'Company_Email': app['company_email'],
                        'Application_Date': app['date'].strftime('%m/%d/%Y'),
                        'Contact_Method': contact_method,
                        'Contact_Information': contact_info,
                        'Result': result,
                        'Physical_Address': app.get('physical_address', '')
                    })
        
        print(f"📄 NC Unemployment CSV report generated: {filename}")
        return filename
    
    def generate_nc_unemployment_pdf(self, weekly_data):
        """Generate PDF report formatted like NC unemployment form"""
        if not REPORTLAB_AVAILABLE:
            print("⚠️  Skipping PDF generation - ReportLab not installed")
            print("Install with: pip install reportlab")
            return None
            
        print("🔄 Generating NC Unemployment PDF...")
        
        # Count outbound applications first
        total_outbound = 0
        for week, applications in weekly_data.items():
            outbound_apps = self.filter_outbound_applications(applications)
            total_outbound += len(outbound_apps)
        
        if total_outbound == 0:
            print("⚠️  No outbound applications found - skipping PDF generation")
            return None
        
        print(f"📊 Found {total_outbound} outbound applications for PDF")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data/NC_Unemployment_Weekly_Report_{timestamp}.pdf"
        
        # Ensure data directory exists
        os.makedirs('data', exist_ok=True)
        
        try:
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
            
            # Sort weeks chronologically
            sorted_weeks = sorted(weekly_data.keys(), 
                                key=lambda x: datetime.strptime(x.replace('Week of ', ''), '%m/%d/%Y'))
            
            week_num = 1
            weeks_added = 0
            
            for week in sorted_weeks:
                applications = weekly_data[week]
                outbound_apps = self.filter_outbound_applications(applications)
                
                if not outbound_apps:  # Skip weeks with no outbound applications
                    continue
                
                print(f"  📅 Processing {week}: {len(outbound_apps)} outbound applications")
                
                # Week header
                week_start = datetime.strptime(week.replace('Week of ', ''), '%m/%d/%Y')
                week_end = week_start + timedelta(days=6)
                
                week_header = f"Week #{week_num} Beginning Sunday (Date): {week_start.strftime('%m/%d/%Y')} Ending Saturday (Date): {week_end.strftime('%m/%d/%Y')}"
                story.append(Paragraph(week_header, styles['Heading2']))
                story.append(Spacer(1, 10))
                
                # Create table data for this week
                table_data = []
                
                # Limit to 3 entries per week (matching the form)
                for i, app in enumerate(outbound_apps[:3]):
                    entry_num = i + 1
                    
                    # Determine contact method and result
                    contact_method = "Email" if app['company_email'] else "LinkedIn"
                    contact_info = app['company_email'] if app['company_email'] else "LinkedIn Profile"
                    
                    if app['is_rejection']:
                        result = "Rejection"
                    elif app['corresponded']:
                        result = "Response"
                    else:
                        result = "No Response"
                    
                    # Create the table row
                    row_data = [
                        [f"{entry_num}. Date of\nContact or\nActivity\n{app['date'].strftime('%m/%d/%Y')}", 
                         f"Company or Activity:\n{app['company_name']}", 
                         f"Contact Name:\n{app['hr_contact']}", 
                         f"Result:\n{result}"],
                        ["", f"Position Sought:\n{app['position']}", 
                         f"Contact Method:\n{contact_method}", ""],
                        ["", "", f"Contact Information:\n{contact_info}", ""]
                    ]
                    
                    table_data.extend(row_data)
                    
                    # Add a separator row if not the last entry
                    if i < min(len(outbound_apps), 3) - 1:
                        table_data.append(["", "", "", ""])
                
                # Create and style the table
                if table_data:
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
                    story.append(Spacer(1, 20))
                
                week_num += 1
                weeks_added += 1
                
                # Add page break between weeks if there are more weeks
                remaining_weeks = [w for w in sorted_weeks[sorted_weeks.index(week)+1:] 
                                 if self.filter_outbound_applications(weekly_data[w])]
                if remaining_weeks:
                    story.append(PageBreak())
            
            # Build PDF
            print(f"  📄 Building PDF with {weeks_added} weeks of data...")
            doc.build(story)
            
            if os.path.exists(filename):
                file_size = os.path.getsize(filename)
                print(f"✅ NC Unemployment PDF generated: {filename}")
                print(f"   File size: {file_size} bytes")
                return filename
            else:
                print("❌ PDF file was not created")
                return None
                
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def show_summary(self, applications, weekly_data):
        """Show summary statistics"""
        print(f"\n📈 SUMMARY REPORT")
        print("=" * 50)
        
        total_apps = len(applications)
        rejections = len([app for app in applications if app['is_rejection']])
        outbound_total = len([app for app in applications if app.get('is_outbound') or app.get('corresponded')])
        
        print(f"Total Applications: {total_apps}")
        print(f"Outbound Applications: {outbound_total}")
        print(f"Rejections Received: {rejections}")
        print(f"Response Rate: {(rejections/total_apps*100):.1f}%" if total_apps > 0 else "N/A")
        
        # Weekly breakdown
        print(f"\nWeekly Breakdown:")
        sorted_weeks = sorted(weekly_data.keys(), 
                            key=lambda x: datetime.strptime(x.replace('Week of ', ''), '%m/%d/%Y'))
        
        for week in sorted_weeks:
            apps = weekly_data[week]
            outbound_apps = self.filter_outbound_applications(apps)
            week_rejections = len([app for app in apps if app['is_rejection']])
            print(f"  {week}: {len(apps)} total, {len(outbound_apps)} outbound, {week_rejections} rejections")
        
        # Company breakdown
        companies = {}
        for app in applications:
            company = app['company_name']
            if company not in companies:
                companies[company] = {'total': 0, 'rejections': 0}
            companies[company]['total'] += 1
            if app['is_rejection']:
                companies[company]['rejections'] += 1
        
        print(f"\nTop Companies Applied To:")
        sorted_companies = sorted(companies.items(), key=lambda x: x[1]['total'], reverse=True)
        for company, stats in sorted_companies[:10]:
            print(f"  {company}: {stats['total']} applications, {stats['rejections']} rejections")
    
    def run_tracker(self):
        """Run the complete job application tracker"""
        print("🚀 Starting Job Application Tracker with NC Unemployment Reports")
        print("=" * 60)
        
        # Load authenticated services
        if not self.load_authenticated_services():
            print("❌ Failed to load authenticated services")
            return False
        
        # Search all accounts
        all_applications = []
        for account in ACCOUNTS:
            if account in self.services:
                apps = self.search_job_related_emails(self.services[account], account)
                all_applications.extend(apps)
        
        if not all_applications:
            print("❌ No job applications found")
            return False
        
        print(f"\n📊 Total applications found: {len(all_applications)}")
        
        # Organize by week
        self.weekly_data = self.organize_by_week(all_applications)
        
        # Generate main CSV
        main_csv = self.generate_csv_report(self.weekly_data)
        
        # Generate NC unemployment reports
        nc_csv = self.generate_nc_unemployment_csv(self.weekly_data)
        nc_pdf = self.generate_nc_unemployment_pdf(self.weekly_data)
        
        # Show summary
        self.show_summary(all_applications, self.weekly_data)
        
        print(f"\n🎉 All reports generated successfully!")
        print(f"📁 Files created:")
        print(f"   📄 Complete report: {main_csv}")
        print(f"   📄 NC unemployment CSV: {nc_csv}")
        if nc_pdf:
            print(f"   📄 NC unemployment PDF: {nc_pdf}")
        else:
            print("   ⚠️  NC unemployment PDF: Not created (see messages above)")
        
        return True

def main():
    """Main function"""
    # Check if reportlab is available, install if needed
    if not REPORTLAB_AVAILABLE:
        try:
            import subprocess
            print("🔄 Installing reportlab for PDF generation...")
            subprocess.check_call(["pip", "install", "reportlab"])
            print("✅ ReportLab installed successfully!")
            print("Please restart the script to enable PDF generation.")
            return
        except Exception as e:
            print(f"⚠️  Could not install ReportLab automatically: {e}")
            print("Install manually with: pip install reportlab")
    
    tracker = JobApplicationTracker()
    success = tracker.run_tracker()
    
    if success:
        print("\n✅ Job application tracking completed successfully!")
        print("Check the 'data' folder for all your reports.")
        
        # List files in data directory
        data_dir = "./data"
        if os.path.exists(data_dir):
            files = [f for f in os.listdir(data_dir) if f.endswith(('.csv', '.pdf'))]
            if files:
                print(f"\n📂 Files in data directory:")
                for file in sorted(files):
                    file_path = os.path.join(data_dir, file)
                    size = os.path.getsize(file_path)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    print(f"   {file} ({size} bytes, {mod_time.strftime('%Y-%m-%d %H:%M:%S')})")
    else:
        print("\n❌ Job application tracking failed.")
        print("Please check the errors above and try again.")

if __name__ == "__main__":
    main()

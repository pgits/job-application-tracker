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
            'indeed': 'Indeed',
            'glassdoor': 'Glassdoor'
        }
        
        return company_mappings.get(company_name.lower(), company_name)
    
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
    
    def search_job_related_emails(self, service, account_email):
        """Search for job-related emails in an account"""
        print(f"🔍 Searching {account_email} for job applications...")
        
        # Search queries for different types of job-related emails
        search_queries = [
            f'after:{START_DATE} (subject:application OR subject:applied OR subject:position OR subject:job)',
            f'after:{START_DATE} (subject:interview OR subject:opportunity OR subject:recruiter)',
            f'after:{START_DATE} ("thank you for applying" OR "unfortunately" OR "not selected")',
            f'after:{START_DATE} (from:linkedin OR from:indeed OR from:glassdoor)',
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
            
            # Extract HR contact
            hr_contact = self.extract_hr_contact(
                message_content['sender'], 
                message_content['sender_email']
            )
            
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
            
            return {
                'date': msg_date,
                'company_name': company_name,
                'hr_contact': hr_contact,
                'company_email': message_content['sender_email'],
                'subject': message_content['subject'],
                'is_rejection': is_rejection,
                'is_outbound': is_outbound,
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
    
    def run_tracker(self):
        """Run the complete job application tracker"""
        print("🚀 Starting Job Application Tracker")
        print("=" * 50)
        
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
        weekly_data = self.organize_by_week(all_applications)
        
        # Generate CSV
        self.generate_csv_report(weekly_data)
        
        # Show summary
        self.show_summary(all_applications, weekly_data)
        
        return True
    
    def generate_csv_report(self, weekly_data):
        """Generate CSV report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data/Job_Application_History_NC_{timestamp}.csv"
        
        # Ensure data directory exists
        os.makedirs('data', exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Week', 'Company_Name', 'HR_Contact', 'Company_Email', 
                'Application_Date', 'Rejection_Status', 'Rejection_Date', 'Notes'
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
                        'HR_Contact': app['hr_contact'],
                        'Company_Email': app['company_email'],
                        'Application_Date': app['date'].strftime('%m/%d/%Y'),
                        'Rejection_Status': rejection_status,
                        'Rejection_Date': rejection_date,
                        'Notes': notes
                    })
        
        print(f"📄 CSV report generated: {filename}")
        return filename
    
    def show_summary(self, applications, weekly_data):
        """Show summary statistics"""
        print(f"\n📈 SUMMARY REPORT")
        print("=" * 50)
        
        total_apps = len(applications)
        rejections = len([app for app in applications if app['is_rejection']])
        
        print(f"Total Applications: {total_apps}")
        print(f"Rejections Received: {rejections}")
        print(f"Response Rate: {(rejections/total_apps*100):.1f}%" if total_apps > 0 else "N/A")
        
        # Weekly breakdown
        print(f"\nWeekly Breakdown:")
        sorted_weeks = sorted(weekly_data.keys(), 
                            key=lambda x: datetime.strptime(x.replace('Week of ', ''), '%m/%d/%Y'))
        
        for week in sorted_weeks:
            apps = weekly_data[week]
            week_rejections = len([app for app in apps if app['is_rejection']])
            print(f"  {week}: {len(apps)} applications, {week_rejections} rejections")
        
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

def main():
    """Main function"""
    tracker = JobApplicationTracker()
    success = tracker.run_tracker()
    
    if success:
        print("\n🎉 Job application tracking completed successfully!")
        print("Check the 'data' folder for your CSV report.")
    else:
        print("\n❌ Job application tracking failed.")
        print("Please check the errors above and try again.")

if __name__ == "__main__":
    main()

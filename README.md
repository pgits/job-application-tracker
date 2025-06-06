# Enhanced Job Application Tracker

An advanced Python application to track job applications across multiple Gmail accounts, extract PDF resume data, prioritize rejections, and generate comprehensive reports including NC unemployment forms.

## 🚀 Features

### Core Functionality
- **Multi-Account Gmail Integration**: Searches across multiple Gmail accounts simultaneously
- **PDF Resume Detection**: Scans ~/Downloads for resume PDFs and matches to applications
- **Priority Ranking System**: Ranks applications by importance (rejections, PDF matches, confirmations)
- **Smart Deduplication**: Eliminates duplicates while preserving unique positions per company
- **NC Unemployment Forms**: Generates official PDF forms matching state requirements

### Advanced Capabilities
- **Rejection Email Detection**: Automatically identifies and prioritizes actual rejection emails
- **Application Confirmation**: Detects confirmation emails proving applications were submitted
- **Company Information Extraction**: Extracts company names, positions, HR contacts, and addresses
- **Comprehensive Reporting**: Generates multiple report formats (CSV, PDF) with detailed analytics

### Data Sources
- **Gmail API**: Searches job-related emails across all configured accounts
- **PDF Text Extraction**: Analyzes resume PDFs for company and position information
- **Smart Filtering**: Excludes irrelevant job sites (ZipRecruiter, iHire, Indeed, LinkedIn alerts)

## 📋 Prerequisites

### Required Software
- Python 3.7 or higher
- Google Cloud Console account
- Access to Gmail accounts you want to track

### Required Python Packages
```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
pip install pandas openpyxl python-dateutil
pip install reportlab  # For PDF generation
pip install PyPDF2     # For PDF text extraction
```

## 🛠️ Setup

### 1. Google Cloud Configuration

#### Enable Gmail API
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Navigate to **APIs & Services > Library**
4. Search for "Gmail API" and click **Enable**

#### Create OAuth Credentials
1. Go to **APIs & Services > Credentials**
2. Click **+ CREATE CREDENTIALS > OAuth 2.0 Client IDs**
3. Choose **Desktop application**
4. Name it "Job Application Tracker"
5. Download the JSON file and save as `credentials.json` in project root

#### Configure OAuth Consent Screen
1. Go to **APIs & Services > OAuth consent screen**
2. Choose **External** user type
3. Fill required information:
   - App name: "Job Application Tracker"
   - User support email: Your primary email
   - Developer contact: Your email
4. Click **SAVE AND CONTINUE** through scopes
5. In **Test users** section, add your Gmail accounts:
   - pgits.job@gmail.com
   - petergits@gmail.com
   - pgits.geekgaps@gmail.com
6. Click **SAVE AND CONTINUE**

### 2. Project Setup

#### Clone and Setup Environment
```bash
# Clone the repository
git clone <your-repo-url>
cd job-application-tracker

# Create virtual environment
python -m venv job_tracker_env

# Activate virtual environment
# Windows:
job_tracker_env\Scripts\activate
# macOS/Linux:
source job_tracker_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### Directory Structure
```
job-application-tracker/
├── job_tracker_env/              # Virtual environment
├── data/                         # Generated reports (auto-created)
├── tokens/                       # Authentication tokens (auto-created)
├── credentials.json              # OAuth credentials (download from Google Cloud)
├── authenticate_accounts.py      # Gmail authentication setup
├── enhanced_job_tracker.py       # Main application
├── requirements.txt              # Python dependencies
├── .gitignore                    # Git ignore rules
└── README.md                     # This file
```

### 3. Authentication Setup

```bash
# Authenticate your Gmail accounts
python authenticate_accounts.py
```

This will open browser windows for each Gmail account. **Important**: Log into the correct account for each authentication prompt.

## 🏃‍♂️ Usage

### Basic Usage
```bash
# Make sure virtual environment is activated
# Run the enhanced tracker
python enhanced_job_tracker.py
```

### Configuration
Edit the `ACCOUNTS` list in `enhanced_job_tracker.py` to modify which Gmail accounts to search:
```python
ACCOUNTS = [
    'your-job-email@gmail.com',
    'your-personal-email@gmail.com',
    'your-other-email@gmail.com'
]
```

## 📊 Output Reports

The application generates three types of reports in the `data/` directory:

### 1. Complete Application Report
**File**: `Job_Application_History_NC_[timestamp].csv`

**Columns**:
- Week, Priority_Score, Company_Name, Position, HR_Contact
- Company_Email, Application_Date, Corresponded, Rejection_Status
- Rejection_Date, Notes, Physical_Address, PDF_Resume_Link
- PDF_Job_Title, PDF_Date

### 2. NC Unemployment Report (CSV)
**File**: `NC_Unemployment_Report_[timestamp].csv`

**Purpose**: Filtered for outbound applications only, formatted for unemployment reporting

### 3. NC Unemployment Form (PDF)
**File**: `NC_Unemployment_Weekly_Report_[timestamp].pdf`

**Purpose**: Official NC Department of Commerce unemployment form with your job search data

## 🎯 Priority Ranking System

Applications are ranked by priority score for maximum relevance:

| Priority Level | Score | Criteria |
|----------------|-------|----------|
| **Highest** | 1000 | Actual rejection emails |
| **Highest** | 1000 | PDF resume + application confirmation |
| **High** | 500 | PDF resume matches (no confirmation) |
| **Medium** | 100 | Outbound applications |
| **Low** | 50 | Email correspondence |
| **Bonus** | 25 | Application confirmation emails |

## 🔄 Deduplication Logic

The system intelligently removes duplicates while preserving important variations:

### What Gets Merged
- Same company + exact same position title
- Example: Multiple emails about "Microsoft Software Engineer"

### What Stays Separate  
- Different positions at same company
- Example: "Microsoft Software Engineer" vs "Microsoft Senior Software Engineer"

### Smart Data Merging
- Keeps rejection status from any email in the group
- Uses best company email (prefers non-noreply addresses)
- Preserves most detailed address information
- Combines all relevant notes and flags

## 🚫 Excluded Content

The tracker automatically filters out:
- **Job Sites**: ZipRecruiter, iHire, Indeed
- **Automated Alerts**: LinkedIn job alerts, job recommendations
- **Spam/Marketing**: No-reply promotional emails

## 🔧 Troubleshooting

### Common Issues

**Authentication Errors**
```bash
# Clear existing tokens and re-authenticate
rm -rf tokens/
python authenticate_accounts.py
```

**Missing Dependencies**
```bash
# Install missing packages
pip install reportlab PyPDF2
```

**PDF Generation Issues**
```bash
# Run diagnostics
python pdf_troubleshoot.py
```

**No Applications Found**
- Check date range in `START_DATE` variable
- Verify Gmail accounts have job-related emails
- Ensure OAuth consent screen includes all test users

### Debug Commands
```bash
# Check authentication status
ls -la tokens/

# Verify file generation
ls -la data/

# Check virtual environment
pip list | grep google
```

## 📈 Sample Output

```
🚀 Starting Enhanced Job Application Tracker with Priority Ranking & Deduplication
================================================================================
✅ ReportLab loaded - PDF generation available
✅ PyPDF2 loaded - PDF text extraction available

🔍 Scanning ~/Downloads for PDF resumes...
📄 Found 15 PDF files in Downloads
  📄 Found resume: Microsoft_SoftwareEngineer_Resume.pdf -> Microsoft
  📄 Found resume: Google_Resume_2025.pdf -> Google
✅ Identified 8 resume files

🔄 Loading authenticated Gmail services...
✅ Loaded service for pgits.job@gmail.com
✅ Loaded service for petergits@gmail.com
✅ Loaded service for pgits.geekgaps@gmail.com

🔍 Searching pgits.job@gmail.com for job applications...
  📧 Found 25 unique messages
  ✅ Processed 18 job-related emails

📊 Total applications found: 45

🔄 Deduplicating applications...
  🔄 Merged 3 applications for Microsoft - Software Engineer
  🔄 Merged 2 applications for Google - Senior Software Engineer
✅ Removed 12 duplicates, kept 33 unique applications

📊 Unique applications after deduplication: 33

📈 ENHANCED SUMMARY REPORT
============================================================
Total Applications: 33
Outbound Applications: 25
PDF Resume Matches: 8
Actual Rejections: 6
Response Rate: 18.2%
📝 Note: Excluded ZipRecruiter, iHire, and Indeed from all results
🔄 Note: Duplicates merged by company + exact position title

Priority Breakdown:
  High Priority (Rejections): 6
  Medium Priority (PDF Matches): 8
  Low Priority (Other): 19

🚨 REJECTION EMAILS (Top Priority):
  • Microsoft - Software Engineer (04/15/2025)
  • Google - Senior Software Engineer (04/10/2025)
  • Amazon - Backend Engineer (04/05/2025)

📄 PDF RESUME MATCHES:
  • Apple - iOS Developer (04/12/2025)
  • Netflix - Full Stack Engineer (04/08/2025)

🎉 All enhanced reports generated successfully!
```

## 🔐 Security & Privacy

### Data Protection
- OAuth tokens stored locally in `tokens/` directory
- No sensitive data transmitted to external servers
- All processing happens locally on your machine

### Files Never Committed to Git
- `credentials.json` - OAuth client secrets
- `tokens/` - Authentication tokens  
- `data/` - Personal job application data
- Virtual environment files

### Best Practices
- Regularly refresh OAuth tokens (automatically handled)
- Keep `credentials.json` secure and never share
- Review `.gitignore` before committing changes

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is for personal use. Ensure compliance with Gmail API Terms of Service and your local employment/privacy laws.

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section
2. Review Google Cloud Console setup
3. Verify all dependencies are installed
4. Ensure virtual environment is activated

## 🔄 Version History

### v2.0.0 - Enhanced Features
- Added PDF resume detection and matching
- Implemented priority ranking system
- Smart deduplication with position preservation
- NC unemployment form generation
- Application confirmation detection

### v1.0.0 - Initial Release
- Basic Gmail API integration
- Simple CSV report generation
- Multi-account support

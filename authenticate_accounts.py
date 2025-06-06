import pickle
import os
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import sys

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Your Gmail accounts
ACCOUNTS = [
    'pgits.job@gmail.com',
    'pgits.geekgaps@gmail.com', 
    'petergits@gmail.com'
]

def authenticate_account(account_email):
    """Authenticate a specific Gmail account"""
    # Create token filename (replace special characters)
    token_file = f'tokens/token_{account_email.replace("@", "_").replace(".", "_")}.pickle'
    creds = None
    
    print(f"\n🔐 Authenticating {account_email}")
    print("-" * 50)
    
    # Load existing token if available
    if os.path.exists(token_file):
        print("📁 Found existing token, loading...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
    
    # Check if credentials are valid
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("🔄 Refreshing expired token...")
            try:
                creds.refresh(Request())
                print("✅ Token refreshed successfully!")
            except Exception as e:
                print(f"❌ Token refresh failed: {e}")
                creds = None
        
        if not creds:
            print("🌐 Opening browser for authentication...")
            print(f"⚠️  IMPORTANT: Make sure to log in as {account_email}")
            input("Press Enter when ready to continue...")
            
            try:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
                print("✅ Authentication successful!")
            except FileNotFoundError:
                print("❌ ERROR: credentials.json file not found!")
                print("Please download it from Google Cloud Console and place it in this directory.")
                return None
            except Exception as e:
                print(f"❌ Authentication failed: {e}")
                return None
        
        # Save the credentials for next time
        try:
            with open(token_file, 'wb') as token:
                pickle.dump(creds, token)
            print(f"💾 Token saved to {token_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not save token: {e}")
    else:
        print("✅ Using existing valid token")
    
    # Build and return the Gmail service
    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except Exception as e:
        print(f"❌ Failed to build Gmail service: {e}")
        return None

def test_account_access(service, account_email):
    """Test Gmail API access for an account"""
    try:
        print(f"\n🧪 Testing access for {account_email}")
        
        # Get user profile to verify correct account
        profile = service.users().getProfile(userId='me').execute()
        actual_email = profile['emailAddress']
        
        if actual_email.lower() != account_email.lower():
            print(f"⚠️  WARNING: Expected {account_email} but got {actual_email}")
            return False
        
        print(f"✅ Confirmed access to: {actual_email}")
        
        # Test message search capability
        results = service.users().messages().list(
            userId='me', 
            q='after:2025/03/27',
            maxResults=5
        ).execute()
        
        message_count = results.get('resultSizeEstimate', 0)
        print(f"📧 Messages since March 27, 2025: {message_count}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing {account_email}: {str(e)}")
        return False

def main():
    """Main function to authenticate all accounts"""
    print("🚀 Gmail API Authentication Setup")
    print("=" * 50)
    
    # Check if credentials.json exists
    if not os.path.exists('credentials.json'):
        print("❌ ERROR: credentials.json not found!")
        print("Please download your OAuth credentials from Google Cloud Console")
        print("and save them as 'credentials.json' in this directory.")
        sys.exit(1)
    
    # Create tokens directory if it doesn't exist
    os.makedirs('tokens', exist_ok=True)
    
    services = {}
    successful_auths = 0
    
    for account in ACCOUNTS:
        service = authenticate_account(account)
        
        if service:
            services[account] = service
            if test_account_access(service, account):
                successful_auths += 1
        else:
            print(f"❌ Failed to authenticate {account}")
        
        print("\n" + "="*50)
    
    # Summary
    print(f"\n📊 SUMMARY")
    print(f"Successfully authenticated: {successful_auths}/{len(ACCOUNTS)} accounts")
    
    if successful_auths == len(ACCOUNTS):
        print("🎉 All accounts ready! You can now run the job tracker.")
    else:
        print("⚠️  Some accounts failed. Please check the errors above.")
    
    return services

if __name__ == "__main__":
    authenticated_services = main()

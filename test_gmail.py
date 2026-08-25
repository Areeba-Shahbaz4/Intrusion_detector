from gmail_integration import get_gmail_service

print("Connecting to Gmail...")

service = get_gmail_service()

print("Gmail connection successful! ✅")

profile = service.users().getProfile(
    userId="me"
).execute()

print("Connected Gmail:", profile.get("emailAddress"))
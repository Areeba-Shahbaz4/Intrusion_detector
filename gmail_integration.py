import os
import base64
from google.oauth2.credentials import Credentials # type: ignore
from google_auth_oauthlib.flow import InstalledAppFlow # type: ignore
from googleapiclient.discovery import build # type: ignore

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.json"


def get_gmail_service():
    creds = None

    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(
            TOKEN_FILE, SCOPES
        )

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            from google.auth.transport.requests import Request # type: ignore
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE,
                SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def fetch_latest_network_file(upload_folder="uploads"):
    service = get_gmail_service()

    os.makedirs(upload_folder, exist_ok=True)

    response = service.users().messages().list(
        userId="me",
        q="has:attachment"
    ).execute()

    messages = response.get("messages", [])

    if not messages:
        raise ValueError(
            "No Gmail messages with attachments were found."
        )

    for item in messages:
        message = service.users().messages().get(
            userId="me",
            id=item["id"],
            format="full"
        ).execute()

        parts = message.get("payload", {}).get("parts", [])

        for part in parts:
            filename = part.get("filename", "")

            if not filename.lower().endswith((".csv", ".txt")):
                continue

            body = part.get("body", {})
            attachment_id = body.get("attachmentId")

            if not attachment_id:
                continue

            attachment = service.users().messages().attachments().get(
                userId="me",
                messageId=item["id"],
                id=attachment_id
            ).execute()

            data = base64.urlsafe_b64decode(
                attachment["data"] + "=="
            )

            safe_name = os.path.basename(filename)
            filepath = os.path.join(
                upload_folder,
                safe_name
            )

            with open(filepath, "wb") as file:
                file.write(data)

            return filepath

    raise ValueError(
        "No CSV or TXT network-traffic attachment was found."
    )
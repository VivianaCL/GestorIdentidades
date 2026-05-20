from pydantic import BaseModel
from typing import List, Optional

class SendSignedEmailRequest(BaseModel):
    to_email: str
    subject: str
    body_text: str
    attachments: Optional[List[str]] = []

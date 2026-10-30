from typing import List, Literal

from fastapi import UploadFile
from api.common.exceptions import InvalidOperationException
from api.common.utils import get_logger
from api.domain.interfaces.email_service import IEmailService
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType, errors
from api.core.config import settings

logger = get_logger(__name__)

class SmtpEmail(IEmailService):
    def __init__(self):
        self.fm = FastMail(
            ConnectionConfig(
                MAIL_USERNAME=settings.smtp_user,
                MAIL_PASSWORD=settings.smtp_password,
                MAIL_FROM=settings.smtp_mail_from,
                MAIL_PORT=settings.smtp_port,
                MAIL_SERVER=settings.smtp_host,
                MAIL_STARTTLS=settings.smtp_starttls,
                MAIL_SSL_TLS=settings.smtp_ssl_tls,
                USE_CREDENTIALS=settings.smtp_use_credentials,
                VALIDATE_CERTS=settings.smtp_validate_certs,
            )
        )

    async def send_email(self, to: str, subject: str, body: str, type: Literal[MessageType.html, MessageType.plain], attachments: List[UploadFile | dict | str] | None = None, raise_on_failure: bool = False) -> None:
        # No mutable default: a shared [] default would be one list object
        # across all calls, so any future mutation (e.g. by a mail library)
        # would leak attachments into later, unrelated emails. None
        # normalizes to a fresh empty list per call instead.
        # Default stays best-effort (log and swallow): several callers send
        # notifications AFTER the action already succeeded (password/email
        # changed, DNS/audit reports), where surfacing a mail failure as an
        # API error would falsely report the completed action as failed.
        # Callers where the email IS the action opt in to raise_on_failure,
        # so a failed send surfaces as a clean 406 InvalidOperationException
        # instead of a false success.
        attachments = attachments if attachments is not None else []
        try:
            logger.info(f"Sending email to {to} with subject '{subject}'")
            if len(attachments) > 0:
                logger.info(f"Email has {len(attachments)} attachments")
                message = MessageSchema(
                    subject=subject,
                    recipients=[to],
                    body=body,
                    subtype=type,
                    attachments=attachments
                )
            else:
                message = MessageSchema(
                    subject=subject,
                    recipients=[to],
                    body=body,
                    subtype=type
                )
            await self.fm.send_message(message)

            logger.info(f"Email sent to {to}")
        except errors.ApiError as e:
            logger.error(f"Failed to send email to {to}: {str(e)}")
            if raise_on_failure:
                raise InvalidOperationException("Failed to send email. Please try again later.")
        except errors.ConnectionErrors as e:
            logger.error(f"Connection error while sending email to {to}: {str(e)}")
            if raise_on_failure:
                raise InvalidOperationException("Failed to send email. Please try again later.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while sending email to {to}: {str(e)}")
            if raise_on_failure:
                raise InvalidOperationException("Failed to send email. Please try again later.")
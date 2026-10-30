from abc import abstractmethod
from typing import List, Literal, Protocol

from fastapi import UploadFile
from fastapi_mail import MessageType


class IEmailService(Protocol):
    @abstractmethod
    async def send_email(self, to: str, subject: str, body: str, type: Literal[MessageType.html, MessageType.plain], attachments: List[UploadFile | dict | str] = [], raise_on_failure: bool = False) -> None:
        raise NotImplementedError
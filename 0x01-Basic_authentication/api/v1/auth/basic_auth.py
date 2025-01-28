#!/usr/bin/env python3
"""
Module Basic_auth for user authentication
"""

from api.v1.auth.auth import Auth
from models.user import User
import base64
from typing import TypeVar, Tuple
from base64 import b64decode


class BasicAuth(Auth):
    """
    Extends the Auth class to implement Basic Authentication.
    """

    def extract_base64_authorization_header(self, auth_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header.

        Args:
            auth_header (str): The Authorization header.

        Returns:
            str: The Base64 encoded part of the header, or None if invalid.
        """
        if auth_header is None or not isinstance(auth_header, str):
            return None
        if not auth_header.startswith('Basic '):
            return None
        return auth_header[6:]  # Remove 'Basic ' prefix.

    def decode_base64_authorization_header(self,
                                           b64_auth_header: str) \
            -> str:
        """
        Decodes the Base64 encoded authorization header.

        Args:
            b64_auth_header (str): Base64 encoded string.

        Returns:
            str: Decoded string, or None if decoding fails.
        """
        if b64_auth_header is None or not isinstance(b64_auth_header, str):
            return None
        try:
            # Decode Base64 string and convert bytes to string.
            decoded_bytes = base64.b64decode(b64_auth_header)
            decoded_str = decoded_bytes.decode('utf-8')
        except Exception:
            return None
        return decoded_str

    def extract_user_credentials(self,
                                 decoded_b64_auth_header: str) \
            -> Tuple[str, str]:
        """
        Extracts the user email and password from the decoded header.

        Args:
            decoded_b64_auth_header (str):
            Decoded authorization string in the format 'email:password'.

        Returns:
            Tuple[str, str]:
            A tuple containing the email and password,
            or (None, None) if invalid.
        """
        if (
            decoded_b64_auth_header is None
            or not isinstance(decoded_b64_auth_header, str)
            or ':' not in decoded_b64_auth_header
        ):
            return None, None
        return decoded_b64_auth_header.split(':', 1)

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Retrieves a
        User object based on the provided email and password.

        Args:
            user_email (str): User's email.
            user_pwd (str): User's password.

        Returns:
            User:
            The user object if valid credentials are found, otherwise None.
        """
        if user_email is None or not isinstance(user_email, str) \
                or user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            # Search for users with the given email.
            users = User.search({'email': user_email})
        except Exception:
            return None

        # Verify the password for each user found.
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user
        based on the request's Authorization header.

        Args:
            request: Flask request object.

        Returns:
            User:
            The authenticated user object, or None if authentication fails.
        """
        # Get the Authorization header from the request.
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None

        # Extract and decode the Base64 authorization header.
        base64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(base64_header)

        # Extract user credentials (email and password).
        user_email, user_password = \
            self.extract_user_credentials(decoded_header)

        # Retrieve the user object from the provided credentials.
        user = self.user_object_from_credentials(user_email, user_password)
        return user

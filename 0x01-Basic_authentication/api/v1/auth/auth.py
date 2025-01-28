#!/usr/bin/env python3
"""
Manage API authentication system
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """
    Manage API authentication methods
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Check if the requested path requires authentication.

        Args:
            path (str): The request path to verify.
            excluded_paths (List[str]): List of paths excluded from authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if not path or not excluded_paths:
            return True

        # Normalize the path and excluded paths for trailing slashes
        if path[-1] != '/':
            path += '/'
        normalized_excluded_paths = [
            p if p[-1] == '/' else p + '/' for p in excluded_paths
        ]

        # Check for wildcard matches
        for excluded_path in normalized_excluded_paths:
            if excluded_path.endswith('*') and path.startswith(excluded_path[:-1]):
                return False

        # Check for exact matches
        if path in normalized_excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieve the Authorization header from the request.

        Args:
            request: Flask request object.

        Returns:
            str: Authorization header value, or None if not present.
        """
        if request is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user based on the request.

        Args:
            request: Flask request object.

        Returns:
            TypeVar('User'): None, as this is meant to be implemented later.
        """
        return None

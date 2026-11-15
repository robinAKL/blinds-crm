"""OAuth resource-server configuration and JWT access-token validation for CRM MCP."""
import json
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

import jwt
from fastapi import HTTPException

MCP_PATH = '/api/mcp'
METADATA_PATH = '/.well-known/oauth-protected-resource' + MCP_PATH
READ = 'crm:read'
WRITE = 'crm:orders:write'
KNOWLEDGE = 'crm:knowledge:read'
SCOPES = (READ, WRITE, KNOWLEDGE)


@dataclass(frozen=True)
class Principal:
    username: str
    scopes: frozenset[str]


def https_url(value, name):
    url = urlsplit(value)
    if (url.scheme != 'https' or not url.hostname or url.username is not None
            or url.query or url.fragment or any(char.isspace() or char in '"\\' for char in value)):
        raise ValueError(f'{name} must be an HTTPS URL without credentials, query or fragment')
    return url


class OAuthResource:
    def __init__(self):
        self.resource = os.environ['VERA_MCP_OAUTH_RESOURCE']
        self.issuer = os.environ['VERA_MCP_OAUTH_ISSUER']
        jwks_url = os.environ['VERA_MCP_OAUTH_JWKS_URL']
        resource_url = https_url(self.resource, 'VERA_MCP_OAUTH_RESOURCE')
        if resource_url.path != MCP_PATH:
            raise ValueError(f'VERA_MCP_OAUTH_RESOURCE must end with {MCP_PATH}')
        https_url(self.issuer, 'VERA_MCP_OAUTH_ISSUER')
        https_url(jwks_url, 'VERA_MCP_OAUTH_JWKS_URL')
        self.metadata_url = f'{resource_url.scheme}://{resource_url.netloc}{METADATA_PATH}'
        self.subjects = json.loads(os.environ['VERA_MCP_OAUTH_SUBJECT_MAP'])
        if not isinstance(self.subjects, dict) or not self.subjects or any(
            not subject.strip() or not isinstance(username, str) or not username.strip()
            for subject, username in self.subjects.items()
        ):
            raise ValueError('VERA_MCP_OAUTH_SUBJECT_MAP must map provider subjects to CRM usernames')
        self.jwks = jwt.PyJWKClient(jwks_url, lifespan=60, timeout=5)

    def metadata(self):
        return {'resource': self.resource, 'authorization_servers': [self.issuer],
                'scopes_supported': list(SCOPES), 'bearer_methods_supported': ['header']}

    def challenge(self, scope=READ, error=None):
        value = f'Bearer resource_metadata="{self.metadata_url}", scope="{scope}"'
        if error == 'insufficient_scope':
            return value + ', error="insufficient_scope", error_description="Additional CRM scope required"'
        if error == 'invalid_token':
            return value + ', error="invalid_token"'
        return value

    def authenticate(self, token):
        try:
            header = jwt.get_unverified_header(token)
            if str(header.get('typ', '')).lower() not in ('at+jwt', 'application/at+jwt'):
                raise jwt.InvalidTokenError('Expected an access token')
            if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str) or not header['kid']:
                raise jwt.InvalidTokenError('Unsupported signing key')
            # Use cached trusted keys. Unknown key IDs must not force a network request.
            key = next((key for key in self.jwks.get_signing_keys() if key.key_id == header['kid']), None)
            if key is None or key.algorithm_name != 'RS256':
                raise jwt.InvalidTokenError('Unknown signing key')
            claims = jwt.decode(token, key.key, algorithms=['RS256'], issuer=self.issuer, audience=self.resource,
                                options={'require': ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id']})
            scope = claims.get('scope', '')
            if not isinstance(scope, str) or any(
                not isinstance(claims[name], str) or not claims[name]
                for name in ('sub', 'jti', 'client_id')
            ):
                raise jwt.InvalidTokenError('Invalid access-token claims')
        except jwt.PyJWKClientConnectionError:
            raise HTTPException(503, 'MCP signing keys are temporarily unavailable') from None
        except (jwt.PyJWTError, ValueError, TypeError, OverflowError):
            raise HTTPException(401, 'Invalid MCP access token',
                                headers={'WWW-Authenticate': self.challenge(error='invalid_token')}) from None
        username = self.subjects.get(claims['sub'])
        if not username:
            raise HTTPException(403, 'OAuth identity has no CRM account')
        return Principal(username, frozenset(scope.split()))


def configured_oauth():
    values = ('VERA_MCP_OAUTH_RESOURCE', 'VERA_MCP_OAUTH_ISSUER',
              'VERA_MCP_OAUTH_JWKS_URL', 'VERA_MCP_OAUTH_SUBJECT_MAP')
    if not any(os.getenv(name) for name in values):
        return None
    if not all(os.getenv(name) for name in values):
        raise ValueError('Configure all VERA_MCP_OAUTH settings to enable OAuth')
    return OAuthResource()

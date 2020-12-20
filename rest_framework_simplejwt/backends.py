import jwt
import logging
from django.utils.translation import gettext_lazy as _
from jwt import InvalidAlgorithmError, InvalidTokenError, algorithms

from .exceptions import TokenBackendError
from .utils import format_lazy

ALLOWED_ALGORITHMS = (
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
)


class TokenBackend:
    def __init__(self, algorithm, signing_key=None, verifying_key=None, audience=None, issuer=None, rotation=None):
        self._validate_algorithm(algorithm)

        self.algorithm = algorithm
        self.rotation = rotation
        self.signing_key = signing_key
        self.audience = audience
        self.issuer = issuer
        if algorithm.startswith('HS') and not rotation:
            self.verifying_key = signing_key
        else:
            self.verifying_key = verifying_key
        if self.rotation:
            self._validate_rotation_settings(algorithm, signing_key, verifying_key)
            self.verifying_key = verifying_key[0:2]

    def _validate_algorithm(self, algorithm):
        """
        Ensure that the nominated algorithm is recognized, and that cryptography is installed for those
        algorithms that require it
        """
        if algorithm not in ALLOWED_ALGORITHMS:
            raise TokenBackendError(format_lazy(_("Unrecognized algorithm type '{}'"), algorithm))

        if algorithm in algorithms.requires_cryptography and not algorithms.has_crypto:
            raise TokenBackendError(format_lazy(_("You must have cryptography installed to use {}."), algorithm))
    
    def _validate_rotation_settings(self, algorithm, signing_key, verifying_key):
        if not isinstance(verifying_key, list) or len(verifying_key) != 3:
            raise TokenBackendError(_('Verifying keys should be list of len 3 with rotation on'))
        if signing_key.public_key() != verifying_key[1]:
            logging.critical(signing_key.public_key())
            logging.critical(verifying_key)
            raise TokenBackendError(_('Signing key\'s public key is not current verify key'))
        if not algorithm.startswith('RS'):
            raise TokenBackendError(_('Rotation possible only for assymetric algorithms'))

    def encode(self, payload):
        """
        Returns an encoded token for the given payload dictionary.
        """
        jwt_payload = payload.copy()
        if self.audience is not None:
            jwt_payload['aud'] = self.audience
        if self.issuer is not None:
            jwt_payload['iss'] = self.issuer

        token = jwt.encode(jwt_payload, self.signing_key, algorithm=self.algorithm)
        if isinstance(token, bytes):
            # For PyJWT <= 1.7.1
            return token.decode('utf-8')
        # For PyJWT >= 2.0.0a1
        return token

    def decode(self, token, verify=True):
        """
        Performs a validation of the given token and returns its payload
        dictionary. 

        Raises a `TokenBackendError` if the token is malformed, if its
        signature check fails, or if its 'exp' claim indicates it has expired.
        """
        if not isinstance(self.verifying_key, list):
            verifying_keys = [self.verifying_key]
        else:
            verifying_keys = self.verifying_key

        last_key = verifying_keys[-1]
        for key in verifying_keys:
            try:
                return jwt.decode(token, key, algorithms=[self.algorithm], verify=verify,
                                audience=self.audience, issuer=self.issuer,
                                options={'verify_aud': self.audience is not None})
            except InvalidAlgorithmError as ex:
                raise TokenBackendError(_('Invalid algorithm specified')) from ex
            except InvalidTokenError:     
                if key == last_key:
                    raise TokenBackendError(_('Token is invalid or expired'))
                continue
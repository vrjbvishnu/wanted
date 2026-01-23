import sys
import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

# Add project root
sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from scheduler_app.okta_validator import main as okta_validator_main
from okta_jwt_verifier.exceptions import (
    JWTInvalidConfigException,
    JWTValidationException,
    JWKException
)

# ---------------------------------------------------------
# SUCCESS CASE (same pattern as email success)
# ---------------------------------------------------------

@pytest.mark.asyncio
@patch("scheduler_app.okta_validator.jwt.decode")
@patch("scheduler_app.okta_validator.IDTokenVerifier")
async def test_okta_success(mock_verifier, mock_jwt_decode):
    # Arrange
    mock_jwt_decode.return_value = {
        "aud": "test-aud",
        "nonce": "abc123"
    }

    mock_instance = mock_verifier.return_value
    mock_instance.verify = AsyncMock(return_value=None)

    # Act
    result = await okta_validator_main("dummy_token")

    # Assert (email-style assertions)
    mock_jwt_decode.assert_called_once()
    mock_instance.verify.assert_called_once_with(
        "dummy_token",
        nonce="abc123"
    )
    assert result == "Token Validated"


# ---------------------------------------------------------
# INVALID CONFIG (email-style failure)
# ---------------------------------------------------------

@pytest.mark.asyncio
@patch("scheduler_app.okta_validator.jwt.decode")
@patch("scheduler_app.okta_validator.IDTokenVerifier")
async def test_okta_invalid_config(mock_verifier, mock_jwt_decode):
    mock_jwt_decode.return_value = {
        "aud": "test-aud",
        "nonce": "abc123"
    }

    mock_instance = mock_verifier.return_value
    mock_instance.verify = AsyncMock(
        side_effect=JWTInvalidConfigException("bad config")
    )

    result = await okta_validator_main("dummy_token")

    mock_instance.verify.assert_called_once()
    assert result == "Token validation Failed."


# ---------------------------------------------------------
# INVALID / EXPIRED TOKEN
# ---------------------------------------------------------

@pytest.mark.asyncio
@patch("scheduler_app.okta_validator.jwt.decode")
@patch("scheduler_app.okta_validator.IDTokenVerifier")
async def test_okta_invalid_token(mock_verifier, mock_jwt_decode):
    mock_jwt_decode.return_value = {
        "aud": "test-aud",
        "nonce": "abc123"
    }

    mock_instance = mock_verifier.return_value
    mock_instance.verify = AsyncMock(
        side_effect=JWTValidationException("expired")
    )

    result = await okta_validator_main("dummy_token")

    mock_instance.verify.assert_called_once()
    assert result == "Token validation Failed."


# ---------------------------------------------------------
# JWK ERROR
# ---------------------------------------------------------

@pytest.mark.asyncio
@patch("scheduler_app.okta_validator.jwt.decode")
@patch("scheduler_app.okta_validator.IDTokenVerifier")
async def test_okta_jwk_error(mock_verifier, mock_jwt_decode):
    mock_jwt_decode.return_value = {
        "aud": "test-aud",
        "nonce": "abc123"
    }

    mock_instance = mock_verifier.return_value
    mock_instance.verify = AsyncMock(
        side_effect=JWKException("jwk error")
    )

    result = await okta_validator_main("dummy_token")

    mock_instance.verify.assert_called_once()
    assert result == "Token validation Failed."
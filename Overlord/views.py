import secrets
import base64
import hashlib
import requests
from datetime import datetime, timedelta
from urllib.parse import urlencode, parse_qs
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.conf import settings
from django.http import JsonResponse
from jose import jwt
from .models import EVEToken

def eve_login(request):
    # Generate state and code verifier for PKCE
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')

    # Store in session
    request.session['oauth_state'] = state
    request.session['code_verifier'] = code_verifier

    # Build authorization URL
    params = {
        'response_type': 'code',
        'redirect_uri': settings.EVE_REDIRECT_URI,
        'client_id': settings.EVE_CLIENT_ID,
        'scope': ' '.join(settings.EVE_SCOPES),
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    auth_url = f"{settings.EVE_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

def eve_callback(request):
    # Verify state parameter
    if request.GET.get('state') != request.session.get('oauth_state'):
        return JsonResponse({'error': 'Invalid state parameter'}, status=400)

    # Get authorization code
    auth_code = request.GET.get('code')
    if not auth_code:
        return JsonResponse({'error': 'Authorization code not provided'}, status=400)

    # Exchange code for tokens - DO NOT include client_id in the body
    token_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': settings.EVE_REDIRECT_URI,
        'code_verifier': request.session.get('code_verifier')  # Only if using PKCE
    }

    # Client credentials ONLY in Authorization header
    auth_string = f"{settings.EVE_CLIENT_ID}:{settings.EVE_CLIENT_SECRET}"
    auth_b64 = base64.b64encode(auth_string.encode('utf-8')).decode('ascii')

    headers = {
        'Authorization': f'Basic {auth_b64}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Django-EVE-App/1.0'
    }

    response = requests.post(settings.EVE_TOKEN_URL, data=token_data, headers=headers)

    if response.status_code != 200:
        return JsonResponse({
            'error': 'Token exchange failed',
            'status': response.status_code,
            'response': response.text
        }, status=400)

    # Continue with token processing...
    token_info = response.json()

    # Decode JWT to get character info
    access_token = token_info['access_token']
    character_data = jwt.get_unverified_claims(access_token)

    # Create or get user
    character_id = character_data['sub'].split(':')[-1]
    character_name = character_data['name']

    user, created = User.objects.get_or_create(
        username=f"eve_{character_id}",
        defaults={'first_name': character_name}
    )

    # Store token information
    expires_at = datetime.now() + timedelta(seconds=token_info['expires_in'])

    EVEToken.objects.update_or_create(
        user=user,
        character_id=character_id,
        defaults={
            'character_name': character_name,
            'access_token': access_token,
            'refresh_token': token_info['refresh_token'],
            'expires_at': expires_at,
            'scopes': token_info.get('scope', '')
        }
    )

    # Log the user in
    login(request, user)

    # Clean up session
    request.session.pop('oauth_state', None)
    request.session.pop('code_verifier', None)

    return redirect('dashboard')  # Redirect to your app's main page


def dashboard(request):
    if request.user.is_authenticated:
        try:
            eve_token = EVEToken.objects.get(user=request.user)
            context = {
                'character_name': eve_token.character_name,
                'character_id': eve_token.character_id,
            }
            return render(request, 'dashboard.html', context)
        except EVEToken.DoesNotExist:
            return redirect('eve_login')
    else:
        return redirect('eve_login')
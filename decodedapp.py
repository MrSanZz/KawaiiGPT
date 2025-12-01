#!/usr/bin/env python3
from flask import Flask, render_template_string, request, jsonify, redirect, url_for, flash, session, send_file, get_flashed_messages, Response
import requests
import json
import os, re
import time
import random
import hashlib
from werkzeug.utils import secure_filename
import tempfile
from datetime import datetime, timedelta
import uuid
import io
import base64
from flask import Response
import json
import threading
from os.path import exists
import gzip
import pickle
from PIL import Image
import io
import html

char_to_binary = {
    'A': '71', 'B': '12', 'C': '930', 'D': '773', 'E': '278', 'F': '446',
    'G': '367', 'H': '73', 'I': '580', 'J': '354', 'K': '403', 'L': '66',
    'M': '529', 'N': '736', 'O': '717', 'P': '502', 'Q': '559', 'R': '500',
    'S': '11', 'T': '228', 'U': '885', 'V': '26', 'W': '640', 'X': '807',
    'Y': '485', 'Z': '435', '1': '921', '2': '499', '3': '429', '4': '320',
    '5': '897', '6': '689', '7': '368', '8': '685', '9': '161', '0': '906',
    '-': '297', '_': '242', '=': '558', '+': '487', '[': '281', '{': '234',
    '}': '864', ']': '447', '\\': '147', '|': '728', ';': '34', ':': '975',
    "'": '457', '"': '371', ',': '537', '<': '190', '.': '822', '>': '152',
    '/': '973', '?': '443', '~': '684', '': '460', '!': '539', '@': '554',
    '#': '746', '$': '131', '%': '364', '^': '715', '&': '276', '*': '322',
    '(': '372', ')': '611', ' ': '851', 'a': '209', 'b': '465', 'c': '568',
    'd': '501', 'e': '944', 'f': '825', 'g': '697', 'h': '577', 'i': '272',
    'j': '341', 'k': '511', 'l': '940', 'm': '686', 'n': '260', 'o': '19',
    'p': '347', 'q': '542', 'r': '703', 's': '339', 't': '919', 'u': '282',
    'v': '800', 'w': '409', 'x': '459', 'y': '99', 'z': '772', '\n': '642',
}
binary_to_char = {v: k for k, v in char_to_binary.items()}

def encrypt_hstry(text):
    encrypted = []
    for char in text:
        if char in char_to_binary:
            encrypted.append(char_to_binary[char])
        else:
            raise ValueError(f"Invalid character: {char}")
    return '.'.join(encrypted)

def decrypt_hstry(binary_text):
    decrypted = []
    for token in binary_text.split('.'):
        if token in binary_to_char:
            decrypted.append(binary_to_char[token])
        else:
            raise ValueError(f"Invalid token: {token}")
    return ''.join(decrypted)

def encrypt_hstr(text):
    return encrypt_hstry(text)

def decrypt_hstr(byte_data):
    return decrypt_hstry(byte_data)

################################################################################

def escape_html_builtin(text, quote=True):
    return html.escape(text, quote=quote)

def escape_html_keep_braces(text, quote=True):
    if text is None:
        return ""
    s = str(text)
    s = html.unescape(s)
    s = s.replace('"', "__NMRACE__").replace("'", "__NRRACE__")
    s = s.replace("{", "__LBRACE__").replace("}", "__RBRACE__")
    s = html.escape(s, quote=quote)
    s = s.replace("__LBRACE__", "{").replace("__RBRACE__", "}")
    s = s.replace("__NMRACE__", '"').replace("__NRRACE__", "'")
    return s

COOKIE_MAX_SIZE = 4500
MAX_CHAT_SESSIONS_IN_COOKIE = 10
MAX_HISTORY_MESSAGES_PER_SESSION = 20

app = Flask(__name__)
app.secret_key = 'your-super-secure-character-manager-secret-key-2024-v3'
app.permanent_session_lifetime = timedelta(hours=24)
templates=None
charsname=None
usernames=None

def compress_image(file_data, quality=25, max_width=800, max_height=600):
    try:
        if hasattr(file_data, 'seek'):
            file_data.seek(0)

        img = Image.open(io.BytesIO(file_data))
        img.verify()
        img = Image.open(io.BytesIO(file_data))

        if img.width > max_width or img.height > max_height:
            img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)

        if img.mode in ('RGBA', 'P', 'LA'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P' and 'transparency' in img.info:
                img = img.convert('RGBA')
            if img.mode == 'RGBA':
                background.paste(img, mask=img.split()[-1])
            else:
                background.paste(img)
            img = background
        elif img.mode == 'L':
            img = img.convert('RGB')

        quality = max(1, min(100, quality))
        output_buffer = io.BytesIO()
        img.save(output_buffer, 
                format='JPEG', 
                quality=quality, 
                optimize=True,
                progressive=quality >= 50)

        compressed_data = output_buffer.getvalue()
        if len(compressed_data) == 0:
            print("Error: Compressed image is empty")
            return file_data

        try:
            Image.open(io.BytesIO(compressed_data)).verify()
        except Exception as verify_error:
            print(f"Compressed image verification failed: {verify_error}")
            return file_data

        return compressed_data

    except Exception as e:
        print(f"Error compressing image: Undf")
        return file_data

def compress_data(data):
    try:
        json_str = json.dumps(data)
        compressed = gzip.compress(json_str.encode('utf-8'))
        return base64.b64encode(compressed).decode('utf-8')
    except Exception as e:
        print(f"Error compressing data: Undf")
        return None

def decompress_data(compressed_str):
    try:
        compressed = base64.b64decode(compressed_str.encode('utf-8'))
        decompressed = gzip.decompress(compressed)
        return json.loads(decompressed.decode('utf-8'))
    except Exception as e:
        print(f"Error decompressing data: Undf")
        return {}

def optimize_user_data_for_cookie(user_data):
    optimized_data = {}

    if 'settings' in user_data:
        optimized_data['settings'] = user_data['settings']

    if 'avatar' in user_data:
        avatar_data = user_data['avatar']
        optimized_data['avatar_meta'] = {
            'content_type': avatar_data.get('content_type'),
            'timestamp': avatar_data.get('timestamp'),
            'has_avatar': True
        }

    if 'chat_sessions' in user_data:
        sessions = user_data['chat_sessions']
        sorted_sessions = sorted(sessions.items(), 
                               key=lambda x: x[1].get('last_updated', 0), 
                               reverse=True)

        optimized_sessions = {}
        for session_id, session_data in sorted_sessions[:MAX_CHAT_SESSIONS_IN_COOKIE]:
            optimized_session = {
                'name': session_data.get('name', ''),
                'character_hash': session_data.get('character_hash', ''),
                'character_name': escape_html_builtin(session_data.get('character_name', '')),
                'created_at': session_data.get('created_at', 0),
                'last_updated': session_data.get('last_updated', 0)
            }

            history = session_data.get('history', [])
            if history:
                optimized_session['history'] = history[-MAX_HISTORY_MESSAGES_PER_SESSION:]
            else:
                optimized_session['history'] = []
            optimized_sessions[session_id] = optimized_session
        optimized_data['chat_sessions'] = optimized_sessions

    return optimized_data

def get_cookie_size(data):
    compressed = compress_data(data)
    return len(compressed) if compressed else 0

@app.before_request
def load_user_data_from_cookies():
    user_id = session.get('user_id')
    if user_id:
        cookie_data = request.cookies.get(f'user_data_{user_id}')
        if cookie_data and user_id not in PERMANENT_USER_CACHE:
            try:
                try:
                    decompressed_data = decompress_data(cookie_data)
                    PERMANENT_USER_CACHE[user_id] = decompressed_data
                except:
                    PERMANENT_USER_CACHE[user_id] = json.loads(cookie_data)
            except Exception as e:
                print(f"Error loading cookie data: Undf")
                pass

@app.after_request
def save_user_data_to_cookies(response):
    user_id = session.get('user_id')
    if user_id and user_id in PERMANENT_USER_CACHE:
        try:
            optimized_data = optimize_user_data_for_cookie(PERMANENT_USER_CACHE[user_id])

            compressed_data = compress_data(optimized_data)
            if compressed_data and len(compressed_data) <= COOKIE_MAX_SIZE:
                existing_cookie = request.cookies.get(f'user_data_{user_id}')

                if compressed_data != existing_cookie:
                    response.set_cookie(
                        f'user_data_{user_id}',
                        compressed_data,
                        max_age=365*24*3600,
                        httponly=True,
                        samesite='Lax'
                    )
            else:
                print(f"Cookie too large ({len(compressed_data) if compressed_data else 0} bytes), skipping save")

        except Exception as e:
            print(f"Error saving cookie: Undf")

    return response


def periodic_cleanup():
    while True:
        try:
            cleanup_expired_cache()

            current_time = time.time()
            thirty_days = 30 * 24 * 3600

            for user_id in list(CHAT_SESSIONS.keys()):
                user_sessions = CHAT_SESSIONS[user_id]
                for session_id in list(user_sessions.keys()):
                    session_data = user_sessions[session_id]
                    if current_time - session_data.get('last_updated', 0) > thirty_days:
                        del user_sessions[session_id]

                if not user_sessions:
                    del CHAT_SESSIONS[user_id]

            for user_id in list(RECENT_CHATS_CACHE.keys()):
                recent_chats = RECENT_CHATS_CACHE[user_id]
                week_ago = current_time - (7 * 24 * 3600)
                RECENT_CHATS_CACHE[user_id] = [
                    chat for chat in recent_chats 
                    if chat['last_chat'] > week_ago
                ]

                if not RECENT_CHATS_CACHE[user_id]:
                    del RECENT_CHATS_CACHE[user_id]

        except Exception as e:
            print(e)

endpoint = {
    'BASE': None,
    'CON': None
}

class ServerCheck:
    def __init__(self):
        self.endpoint = {"BASE": "", "CON": ""}

    def check_server(self):
        self.github_url = {
            "BASE": "https://raw.githubusercontent.com/MrSanZz/glass/refs/heads/main/base.txt",
            "CON": "https://raw.githubusercontent.com/MrSanZz/glass/refs/heads/main/con.txt"
        }
        for subdict, key in self.github_url.items():
            kys=str(requests.get(key).text).split()[0]
            self.resp=decrypt_hstr(kys)
            self.endpoint[subdict]=self.resp

    def feedback_server(self):
        self.check_server()
        return self.endpoint

def CallAPI():
    global endpoint
    endp = ServerCheck().feedback_server()
    for subdict, key in endp.items():
        endpoint[subdict]=key

#CallAPI()
BASE_URL = endpoint['BASE']
CHAT_API_URL = endpoint['CON']
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
MAX_FILE_SIZE = 2 * 1024 * 1024
PERMANENT_USER_CACHE = {}  # {user_id: persistent_data}
RECENT_CHATS_CACHE = {}    # {user_id: [recent_character_hashes]}
DEFAULT_GREETING = "Hello there!"

IMAGE_CACHE = {}
CACHE_DURATION = 300
CHAT_SESSIONS = {}  # {user_id: {session_id: conversation_history}}

@app.route('/')
def enhanced_index():
    user_id = get_user_id()
    user_profile = get_user_profile()

    characters = get_random_characters(15)
    content = render_template_string(INDEX_TEMPLATE, 
                                   characters=characters)

    return render_template_string(BASE_TEMPLATE,
                                title="RoleYU - Discover Amazing AI Characters", 
                                content=content,
                                user_profile=user_profile,
                                navbar_content=render_navbar(user_profile),
                                flash_messages=render_flash_messages(),
                                bottom_nav=BOTTOM_NAV_TEMPLATE,
                                custom_scripts="")

def render_navbar(user_profile):
    try:
        user_id = session.get('user_id', 'Anonymous')
        avatar_html = get_avatar_html(user_profile)

        return f"""
        <nav class="navbar navbar-expand-lg navbar-dark">
            <div class="container">
                <a class="navbar-brand" href="/">
                    <i class="fas fa-robot me-2"></i>RoleYU
                </a>
                <div class="navbar-nav ms-auto">
                    <div class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            {avatar_html}
                            {escape_html_builtin(user_profile.get('name', 'User'))}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="/profile"><i class="fas fa-cog me-1"></i>Profile</a></li>
                            <li><a class="dropdown-item" href="/my-characters"><i class="fas fa-robot me-1"></i>My Characters</a></li>
                            <li><a class="dropdown-item" href="/add"><i class="fas fa-plus me-1"></i>Create Character</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><span class="dropdown-item-text small text-muted">ID: {user_id[:8]}...</span></li>
                        </ul>
                    </div>
                </div>
            </div>
        </nav>
        """
    except Exception as e:
        print(f"Error rendering navbar: Undf")
        return f"""
        <nav class="navbar navbar-expand-lg navbar-dark">
            <div class="container">
                <a class="navbar-brand" href="/">
                    <i class="fas fa-robot me-2"></i>RoleYU
                </a>
            </div>
        </nav>
        """

def get_avatar_html(user_profile):
    try:
        if user_profile.get('avatar_token'):
            return f'<img src="/temp_image/{user_profile["avatar_token"]}" alt="Profile" class="user-avatar me-1">'
        else:
            return '<i class="fas fa-user-circle me-1"></i>'
    except Exception as e:
        print(f"Error generating avatar HTML: Undf")
        return '<i class="fas fa-user-circle me-1"></i>'

def get_flash_messages_manual():
    try:
        flashes = session.get('_flashes', [])
        session.pop('_flashes', None)
        return flashes
    except Exception as e:
        print(f"Error getting flash messages manually: Undf")
        return []

def render_flash_messages_manual():
    try:
        messages = get_flash_messages_manual()
        if not messages:
            return ""

        html = ""
        for message_data in messages:
            if isinstance(message_data, tuple) and len(message_data) >= 2:
                category, message = message_data[0], message_data[1]
            else:
                category, message = 'info', str(message_data)

            alert_class = 'danger' if category == 'error' else 'success'
            icon = 'exclamation-triangle' if category == 'error' else 'check-circle'
            html += f"""
            <div class="alert alert-{alert_class} alert-dismissible fade show" role="alert">
                <i class="fas fa-{icon} me-2"></i>
                {message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            """
        return html
    except Exception as e:
        print(f"Error rendering flash messages manually: Undf")
        return ""

def safe_get_flashed_messages():
    try:
        from flask import get_flashed_messages
        return get_flashed_messages(with_categories=True)
    except ImportError:
        print("Warning: get_flashed_messages not available, using manual implementation")
        return get_flash_messages_manual()
    except Exception as e:
        print(f"Error with get_flashed_messages: Undf")
        return []

def render_flash_messages():
    messages = get_flashed_messages(with_categories=True)
    if not messages:
        return ""

    html = ""
    for category, message in messages:
        alert_class = 'danger' if category == 'error' else 'success'
        icon = 'exclamation-triangle' if category == 'error' else 'check-circle'
        html += f"""
        <div class="alert alert-{alert_class} alert-dismissible fade show" role="alert">
            <i class="fas fa-{icon} me-2"></i>
            {message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        """
    return html

def allowed_file(filename):
    filtered = True if '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS else False
    return filtered

def get_user_id():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
        session.permanent = True
    return session['user_id']

def get_user_profile():
    user_id = get_user_id()
    profile = session.get('user_profile', {})

    defaults = {
        'name': f'User_{user_id[:8]}',
        'personalities': 'Friendly and curious person who loves to chat',
        'avatar_token': None
    }

    for key, default_value in defaults.items():
        if key not in profile:
            profile[key] = default_value

    session['user_profile'] = profile
    return profile

def save_user_profile(name, personalities, avatar_token=None):
    global usernames
    profile = get_user_profile()
    profile['name'] = name
    profile['personalities'] = personalities
    profile['avatar_token'] = avatar_token

    #save_user_data_to_cookies(profile)

    session['user_profile'] = profile
    usernames=profile['name']
    return profile

def get_user_permanent_data():
    user_id = get_user_id()
    if user_id not in PERMANENT_USER_CACHE:
        cookie_data = request.cookies.get(f'user_data_{user_id}')
        if cookie_data:
            try:
                import json
                PERMANENT_USER_CACHE[user_id] = json.loads(cookie_data)
            except:
                PERMANENT_USER_CACHE[user_id] = {}
        else:
            PERMANENT_USER_CACHE[user_id] = {}

    return PERMANENT_USER_CACHE[user_id]

def save_user_permanent_data(data):
    user_id = get_user_id()
    PERMANENT_USER_CACHE[user_id] = data
    return data

def get_permanent_chat_sessions(user_id):
    permanent_data = get_user_permanent_data()
    return permanent_data.get('chat_sessions', {})

def save_permanent_chat_session(user_id, session_id, session_data):
    permanent_data = get_user_permanent_data()
    if 'chat_sessions' not in permanent_data:
        permanent_data['chat_sessions'] = {}

    permanent_data['chat_sessions'][session_id] = {
        'name': session_data.get('name', f'Chat {len(permanent_data["chat_sessions"]) + 1}'),
        'character_hash': session_data.get('character_hash'),
        'character_name': escape_html_builtin(session_data.get('character_name')),
        'history': session_data.get('history', []),
        'created_at': session_data.get('created_at', time.time()),
        'last_updated': time.time()
    }

    sessions = permanent_data['chat_sessions']
    if len(sessions) > 25:
        sorted_sessions = sorted(sessions.items(), 
                               key=lambda x: x[1].get('last_updated', 0))
        for old_session_id, _ in sorted_sessions[:-50]:
            del sessions[old_session_id]

    save_user_permanent_data(permanent_data)

def delete_permanent_chat_session(user_id, session_id):
    permanent_data = get_user_permanent_data()
    if 'chat_sessions' in permanent_data and session_id in permanent_data['chat_sessions']:
        del permanent_data['chat_sessions'][session_id]
        save_user_permanent_data(permanent_data)
        return True
    return False

def rename_chat_session(user_id, session_id, new_name):
    permanent_data = get_user_permanent_data()
    if 'chat_sessions' in permanent_data and session_id in permanent_data['chat_sessions']:
        permanent_data['chat_sessions'][session_id]['name'] = new_name
        save_user_permanent_data(permanent_data)
        return True
    return False

def add_to_recent_chats(user_id, character_hash, character_name):
    if user_id not in RECENT_CHATS_CACHE:
        RECENT_CHATS_CACHE[user_id] = []

    RECENT_CHATS_CACHE[user_id] = [item for item in RECENT_CHATS_CACHE[user_id] 
                                   if item['hash'] != character_hash]

    RECENT_CHATS_CACHE[user_id].insert(0, {
        'hash': character_hash,
        'name': character_name,
        'last_chat': time.time()
    })

    RECENT_CHATS_CACHE[user_id] = RECENT_CHATS_CACHE[user_id][:15]

def get_recent_chats(user_id):
    return RECENT_CHATS_CACHE.get(user_id, [])

def format_greeting(template, user_name, char_name):
    if not template:
        return f"Hello! I am {char_name}. Nice to meet you! 😊"
    return (template
            .replace("{{user}}", user_name)
            .replace("{{char}}", char_name))

def get_random_characters(limit=15):
    try:
        all_characters = CharacterAPI.get_characters()
        char_list = []

        for char_name, char_versions in all_characters.items():
            if isinstance(char_versions, list):
                for char_data in char_versions:
                    if isinstance(char_data, dict):
                        if 'greetings' not in char_data and 'greeting' not in char_data:
                            char_data['greetings'] = DEFAULT_GREETING
                        elif 'greeting' in char_data and 'greetings' not in char_data:
                            char_data['greetings'] = char_data['greeting']
                    char_list.append((char_name, char_data))
            else:
                if isinstance(char_versions, dict):
                    if 'greetings' not in char_versions and 'greeting' not in char_versions:
                        char_versions['greetings'] = DEFAULT_GREETING
                    elif 'greeting' in char_versions and 'greetings' not in char_versions:
                        char_versions['greetings'] = char_versions['greeting']
                char_list.append((char_name, char_versions))
        import random
        random.shuffle(char_list)
        return char_list[:limit]
    except Exception as e:
        print(f"Error getting random characters: Undf")
        return []

def search_characters(query):
    try:
        all_characters = CharacterAPI.get_characters()
        results = []
        query_lower = query.lower()
        for char_name, char_versions in all_characters.items():
            if isinstance(char_versions, list):
                for char_data in char_versions:
                    if isinstance(char_data, dict) and 'greetings' not in char_data:
                        char_data['greetings'] = DEFAULT_GREETING

                    if (query_lower in char_name.lower() or 
                        (isinstance(char_data, dict) and 
                         (query_lower in char_data.get('description', '').lower() or
                          query_lower in char_data.get('greetings', '').lower()))):
                        results.append((escape_html_builtin(char_name), char_data))
            else:
                if isinstance(char_versions, dict) and 'greetings' not in char_versions:
                    char_versions['greetings'] = DEFAULT_GREETING

                if (query_lower in char_name.lower() or
                    (isinstance(char_versions, dict) and
                     query_lower in char_versions.get('greetings', '').lower())):
                    results.append((escape_html_builtin(char_name), escape_html_builtin(char_versions)))

        return results
    except Exception as e:
        print(f"Error searching characters: Undf")
        return []

def get_user_settings():
    user_id = get_user_id()
    permanent_data = get_user_permanent_data()
    return permanent_data.get('settings', {
        'theme': 'light',
        'ai_model': PERMANENT_USER_CACHE[user_id]['settings']['ai_model'] if 'settings' in PERMANENT_USER_CACHE else 'Fluffball' or 'Fluffball',
        'language': 'en'
    })

def save_user_settings(settings):
    permanent_data = get_user_permanent_data()
    permanent_data['settings'] = settings
    save_user_permanent_data(permanent_data)

def get_user_avatar_permanent():
    user_id = get_user_id()
    permanent_data = get_user_permanent_data()

    avatar_meta = permanent_data.get('avatar')
    if avatar_meta and isinstance(avatar_meta, dict):
        token = avatar_meta.get('token')
        if token and token in IMAGE_CACHE:
            return token

    return None

def cache_user_avatar(avatar_file):
    try:
        user_id = get_user_id()
        permanent_data = get_user_permanent_data()

        avatar_data = {
            'data': base64.b64encode(avatar_file.read()).decode('utf-8'),
            'content_type': avatar_file.content_type,
            'timestamp': time.time()
        }

        permanent_data['avatar'] = avatar_data
        save_user_permanent_data(permanent_data)

        return get_user_avatar_permanent()
    except Exception as e:
        print(f"Error saving permanent avatar: Undf")
        return None

def get_chat_sessions(user_id):
    if user_id not in CHAT_SESSIONS:
        CHAT_SESSIONS[user_id] = {}
    return CHAT_SESSIONS[user_id]

def save_chat_session(user_id, session_id, conversation_history, char_name=""):
    if user_id not in CHAT_SESSIONS:
        CHAT_SESSIONS[user_id] = {}

    CHAT_SESSIONS[user_id][session_id] = {
        'history': conversation_history,
        'character_name': escape_html_builtin(char_name),
        'created_at': time.time(),
        'last_updated': time.time()
    }

def delete_message_from_history(user_id, session_id, message_index):
    try:
        if user_id in CHAT_SESSIONS and session_id in CHAT_SESSIONS[user_id]:
            history = CHAT_SESSIONS[user_id][session_id]['history']
            if 0 <= message_index < len(history):
                del history[message_index]
                CHAT_SESSIONS[user_id][session_id]['last_updated'] = time.time()
                return True
    except Exception as e:
        print(f"Error deleting message: Undf")
    return False

def edit_message_in_history(user_id, session_id, message_index, new_content):
    try:
        if user_id in CHAT_SESSIONS and session_id in CHAT_SESSIONS[user_id]:
            history = CHAT_SESSIONS[user_id][session_id]['history']
            if 0 <= message_index < len(history):
                history[message_index]['content'] = new_content
                CHAT_SESSIONS[user_id][session_id]['last_updated'] = time.time()
                return True
    except Exception as e:
        print(f"Error editing message: Undf")
    return False

def clean_text(text):
    emoticon = [':3', '>w<', 'owo', ':d', ':p', '>:(', '>:)', ':)', ':(', 'uwu', ':/', ':|', ';)', ';d', ';p', '><', '^^', ';(', ':o', ';o', ';0', ':0', ';]', ':]', ';}', ':}', 'xd', '^o^', '^w^', '^~^']
    for filter_emoti in emoticon:
        text = text.lower().replace(filter_emoti, '')
    text = re.sub(r"(?<!\*)\*[^*]+\*(?!\*)", "", text)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"[^a-zA-Z0-9\s,.!~?]", "", text)
    text = text.strip()
    return text

def cache_character_image(char_hash, photo_filename):
    try:
        response = requests.get(f"{BASE_URL}/char_photo/{photo_filename}", timeout=10)
        if response.status_code == 200:
            temp_token = hashlib.sha256(f"{char_hash}-{photo_filename}-{time.time()}".encode()).hexdigest()[:16]

            IMAGE_CACHE[temp_token] = {
                'data': response.content,
                'content_type': response.headers.get('content-type', 'image/jpeg'),
                'expires': time.time() + CACHE_DURATION
            }

            return temp_token
    except Exception as e:
        print(f"Error caching image: Undf")
    return None

def get_cached_image(token):
    if token in IMAGE_CACHE:
        cache_entry = IMAGE_CACHE[token]
        if cache_entry['expires'] > time.time():
            return cache_entry
        else:
            del IMAGE_CACHE[token]
    return None

def cleanup_expired_cache():
    current_time = time.time()
    expired_tokens = [token for token, data in IMAGE_CACHE.items() if data['expires'] <= current_time]
    for token in expired_tokens:
        del IMAGE_CACHE[token]

class ChatEngine:
    def __init__(self):
        user_id = get_user_id()
        self.llm_model = {
            "Fluffball": {
                "model_name": "openai-large",
                "provider": "PollinationsAI",
                "display_name": "Fluffball - More intellegent"
            },
            "Softball": {
                "model_name": "openai-reasoning",
                "provider": "PollinationsAI",
                "display_name": "Softball - Chills conversation"
            },
            "Canyon": {
                "model_name": "openai",
                "provider": "PollinationsAI",
                "display_name": "Canyon - Intellegent"
            },
            "Diablo": {
                "model_name": "evil",
                "provider": "PollinationsAI",
                "display_name": "Diablo - Spicy"
            }
        }
        try:
            self.base_model = PERMANENT_USER_CACHE[user_id]['settings']['ai_model'] if PERMANENT_USER_CACHE[user_id] is not None else 'Fluffball'
        except:
            self.base_model = 'Fluffball'
        #print(f"uid settings ai model: {PERMANENT_USER_CACHE[user_id]['settings']['ai_model'] if PERMANENT_USER_CACHE[user_id] is not None else 'Fluffball'}")
        #print(PERMANENT_USER_CACHE[user_id]['settings']['ai_model'])

    def get_available_models(self):
        return {k: v['display_name'] for k, v in self.llm_model.items()}

    def send_to_ai(self, conversation_history, model=None):
        if model is None:
            model = self.base_model

        provider = self.llm_model[model]['provider']
        model_name = self.llm_model[model]['model_name']

        try:
            non_system_messages = [msg for msg in conversation_history if msg["role"] != "system"]
            if len(non_system_messages) > 35:
                excess = len(non_system_messages) - 35
                count = 0
                new_history = []
                for msg in conversation_history:
                    if msg["role"] == "system":
                        new_history.append(msg)
                    else:
                        if count < excess:
                            count += 1
                            continue
                        new_history.append(msg)
                conversation_history = new_history

            conversation_id = "".join(random.choice("1234567890") for _ in range(19))
            payload = {
                "id": conversation_id,
                "conversation_id": "9cdcb572-e957-415a-9529-222f92c4cd08",
                "conversation": None,
                "model": model_name,
                "max_tokens": 5290,
                "web_search": False,
                "provider": provider,
                "messages": conversation_history,
                "action": None,
                "download_media": True,
                "api_key": None,
                "ignored": ["Anthropic","BlackboxPro","CablyAI","Cerebras","DeepInfra","DeepSeek","GigaChat","GithubCopilot","GlhfChat","Gemini","GeminiPro","Grok","Groq","HuggingChat","MicrosoftDesigner","BingCreateImages","MiniMax","OpenaiAPI","OpenRouter","PerplexityApi","PuterJS","Reka","Replicate","ThebApi","WhiteRabbitNeo","xAI"],
                "aspect_ratio": "16:9"
            }

            response = requests.post(
                CHAT_API_URL,
                headers={
                    "content-type": "application/json",
                    "User-Agent": "KawaiiGPTc-4-api ROLEPLAY"
                }, 
                data=json.dumps(payload), 
                stream=True,
                timeout=30
            )

            if response.status_code != 200:
                return None

            return response

        except Exception as e:
            print(f"Error sending to AI: Undf")
            return None

    def is_response_bad(self, sentence_list):
        if not sentence_list or (len(sentence_list) > 0 and sentence_list[0].strip() == ""):
            return True
        bad_phrases = ["i'm sorry", "i apologize", "i can't", "i cannot", "i am not able"]
        first_sentence = sentence_list[0].lower() if sentence_list else ""
        return any(bad_phrase in first_sentence for bad_phrase in bad_phrases)

    def get_valid_response(self, conversation_history, max_retry=3):
        retries = 0
        while retries < max_retry:
            response = self.send_to_ai(conversation_history)
            if not response:
                retries += 1
                time.sleep(1)
                continue

            final_sentence = []
            try:
                for line in response.iter_lines(decode_unicode=True):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if data.get("type") == "content":
                                content = data["content"]
                                if 'Support Pollinations' in content:
                                    continue
                                if '**Sponsor**' not in content and 'Sponsor' not in clean_text(content):
                                    if content == '502 Bad Gateway\nUnable to reach the origin service. The service may be down or it may not be responding to traffic from cloudflared\n':
                                        content = "Sorry! Server's currently maintenance due to high usage traffic, please try again later. 😊"
                                    final_sentence.append(content)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Error processing response: Undf")
                retries += 1
                continue

            if not self.is_response_bad(final_sentence):
                return ''.join(final_sentence)

            retries += 1
            time.sleep(1)

        return "[FILTERED] Please have a normal conversation and know ethics"

class CharacterAPI:
    @staticmethod
    def get_characters():
        try:
            response = requests.get(f"{BASE_URL}/character.json", timeout=10)
            if response.status_code == 200:
                data = response.json().get("RP-GPTv2-API", {})
                normalized_data = {}
                for char_name, char_versions in data.items():
                    if isinstance(char_versions, list):
                        normalized_versions = []
                        for item in char_versions:
                            if isinstance(item, dict):
                                if 'greetings' not in item:
                                    item['greetings'] = DEFAULT_GREETING

                                if item.get('photo'):
                                    photo_token = cache_character_image(item.get('hash', ''), item['photo'])
                                    if photo_token:
                                        item['photo_token'] = photo_token
                                normalized_versions.append(item)
                            else:
                                normalized_versions.append({
                                    "personalities": str(item),
                                    "style": "",
                                    "description": "",
                                    "greetings": DEFAULT_GREETING,
                                    "hash": f"legacy-{hash(str(item))}"
                                })
                        normalized_data[char_name] = normalized_versions
                    elif isinstance(char_versions, dict):
                        if 'greetings' not in char_versions:
                            char_versions['greetings'] = DEFAULT_GREETING

                        if char_versions.get('photo'):
                            photo_token = cache_character_image(char_versions.get('hash', ''), char_versions['photo'])
                            if photo_token:
                                char_versions['photo_token'] = photo_token
                        normalized_data[char_name] = [char_versions]
                    else:
                        normalized_data[char_name] = [{
                            "personalities": str(char_versions),
                            "style": "",
                            "description": "",
                            "greetings": DEFAULT_GREETING,
                            "hash": f"legacy-{hash(str(char_versions))}"
                        }]
                return normalized_data
            return {}
        except Exception as e:
            print(f"Error getting characters: Undf")
            return {}

    @staticmethod
    def get_character_by_hash(char_hash):
        try:
            characters = CharacterAPI.get_characters()
            for char_name, char_versions in characters.items():
                for char_data in char_versions:
                    if isinstance(char_data, dict) and char_data.get('hash') == char_hash:
                        return char_name, char_data
            return None, None
        except Exception as e:
            print(f"Error getting character by hash: Undf")
            return None, None

    @staticmethod
    def add_character(name, personalities, style, description, greeting, photo_file=None, creator_id=None):
        try:
            if not greeting or greeting.strip() == "":
                greeting = DEFAULT_GREETING
            if len(name) > 1000:
                return {"status": "error", "message": "Character name's too long! max: 1000 chars"}
            elif len(personalities) > 1000:
                return {"status": "error", "message": "Character personalities's too long! max: 1000 chars"}
            elif len(style) > 1000:
                return {"status": "error", "message": "Character style's too long! max: 1000 chars"}
            elif len(description) > 1000:
                return {"status": "error", "message": "Character title's too long! max: 1000 chars"}
            elif len(greeting) > 1000:
                return {"status": "error", "message": "Character greetings's too long! max: 1000 chars"}
            else:
                pass

            data = {
                "RP-GPTv2-API": {
                    name: {
                        "personalities": personalities,
                        "style": style,
                        "description": description,
                        "greetings": escape_html_keep_braces(greeting),
                        "creator_id": creator_id
                    }
                }
            }

            files = {}
            multipart_data = {
                'data': json.dumps(data)
            }

            if photo_file:
                photo_content = photo_file.read()
                compressed_photo = compress_image(photo_content, quality=50, max_width=500, max_height=500)
                files[name] = (photo_file.filename, compressed_photo, photo_file.content_type)

            response = requests.post(
                f"{BASE_URL}/",
                data=multipart_data,
                files=files,
                timeout=30
            )

            return response.json() if response.status_code == 200 else {"status": "error", "message": "Failed to add character"}

        except Exception as e:
            print(f"Error adding character: Undf")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def remove_character(hash_id, user_id):
        try:
            char_name, char_data = CharacterAPI.get_character_by_hash(hash_id)
            if not char_data:
                return {"status": "error", "message": "Character not found"}

            if char_data.get('creator_id') != user_id:
                return {"status": "error", "message": "Access denied: You can only delete your own characters"}

            response = requests.post(
                f"{BASE_URL}/",
                data={'remove_hash': hash_id},
                timeout=10
            )

            return response.json() if response.status_code == 200 else {"status": "error", "message": "Failed to remove character"}
        except Exception as e:
            print(f"Error removing character: Undf")
            return {"status": "error", "message": str(e)}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; font-family: 'Segoe UI', system-ui, sans-serif; }
        .main-container { background: rgba(255,255,255,0.95); border-radius: 20px; margin-top: 20px; margin-bottom: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); }
        .character-card { 
            transition: all 0.3s ease; height: 100%; border: none; border-radius: 15px; 
            background: linear-gradient(145deg, #ffffff, #f0f0f0); 
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        .character-card:hover { 
            transform: translateY(-10px); 
            box-shadow: 0 15px 35px rgba(0,0,0,0.15);
        }
        .character-photo { 
            width: 80px; height: 80px; object-fit: cover; border-radius: 50%; 
            border: 3px solid #6f42c1; box-shadow: 0 4px 15px rgba(111,66,193,0.3);
        }
        .navbar { background: rgba(111,66,193,0.95) !important; backdrop-filter: blur(10px); }
        .navbar-brand { font-weight: bold; color: white !important; }
        .btn-primary { 
            background: linear-gradient(45deg, #6f42c1, #8b5cf6); 
            border: none; border-radius: 25px; padding: 10px 25px;
            transition: all 0.3s ease;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(111,66,193,0.4); }
        .btn-danger { 
            background: linear-gradient(45deg, #dc3545, #ff6b6b);
            border: none; border-radius: 25px;
        }
        .btn-success { 
            background: linear-gradient(45deg, #28a745, #20c997);
            border: none; border-radius: 25px;
        }
        .form-control, .form-select { border-radius: 15px; border: 2px solid #e9ecef; }
        .form-control:focus { border-color: #6f42c1; box-shadow: 0 0 0 0.2rem rgba(111,66,193,0.25); }
        .card { border-radius: 15px; border: none; }
        .alert { border-radius: 15px; border: none; }
        .modal-content { border-radius: 20px; border: none; }
        .empty-state { padding: 60px 20px; text-align: center; }
        .empty-state i { color: rgba(111,66,193,0.3); }
        .hash-badge { 
            background: rgba(111,66,193,0.1); 
            color: #6f42c1; 
            padding: 2px 8px; 
            border-radius: 10px; 
            font-size: 0.75rem;
        }
        .stats-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            margin-bottom: 20px;
        }
        .owner-badge {
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.7rem;
        }
        .user-avatar {
            width: 35px; height: 35px; object-fit: cover; border-radius: 50%;
            border: 2px solid rgba(255,255,255,0.8);
        }
        /* Add these new styles for enhanced features */
        .search-container {
            position: relative;
            margin-bottom: 20px;
        }
        
        .search-results {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #ddd;
            border-radius: 10px;
            max-height: 300px;
            overflow-y: auto;
            z-index: 1000;
            display: none;
        }
        
        .search-result-item {
            padding: 10px 15px;
            cursor: pointer;
            border-bottom: 1px solid #eee;
        }
        
        .search-result-item:hover {
            background-color: #f8f9fa;
        }
        
        .typing-indicator-chat {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 8px 12px;
            background: rgba(111, 66, 193, 0.1);
            border-radius: 15px;
        }
        
        .typing-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background-color: #6f42c1;
            animation: typing-animation 1.5s infinite;
        }
        
        .typing-dot:nth-child(2) { animation-delay: 0.2s; }
        .typing-dot:nth-child(3) { animation-delay: 0.4s; }
        
        @keyframes typing-animation {
            0%, 60%, 100% { opacity: 0.3; transform: scale(0.8); }
            30% { opacity: 1; transform: scale(1); }
        }
        
        .session-name-editable {
            background: transparent;
            border: none;
            color: inherit;
            width: 100%;
            font-weight: bold;
        }
        
        .session-name-editable:focus {
            outline: 1px solid #6f42c1;
            background: rgba(111, 66, 193, 0.1);
            border-radius: 4px;
            padding: 2px 4px;
        }
        
        .character-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 100px; /* Space for bottom nav */
        }
        
        @media (max-width: 768px) {
            .character-grid {
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                gap: 15px;
            }
        }
    </style>
</head>
<body>
    {{ navbar_content | safe }}
    <div class="container">
        <div class="main-container p-4">
            {{ flash_messages | safe }}
            {{ content | safe }}
        </div>
    </div>
    {{ bottom_nav | safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {{ custom_scripts | safe }}
</body>
</html>
"""

INDEX_TEMPLATE = """
<div class="d-flex justify-content-between align-items-center mb-4">
    <div>
        <h1><i class="fas fa-users me-2 text-primary"></i>Discover Characters</h1>
        <p class="text-muted">Chat with amazing AI personalities</p>
    </div>
    <a href="/add" class="btn btn-primary btn-lg">
        <i class="fas fa-plus me-1"></i>Create Character
    </a>
</div>

<div class="search-container">
    <div class="input-group">
        <input type="text" class="form-control" id="character-search" 
               placeholder="Search characters by name or personality..." 
               onkeyup="searchCharacters(this.value)">
        <button class="btn btn-outline-primary" type="button">
            <i class="fas fa-search"></i>
        </button>
    </div>
    <div class="search-results" id="search-results"></div>
</div>

<div id="characters-container">
    {% if characters %}
        <div class="character-grid">
            {% for char_name, char_data in characters %}
            <div class="card character-card h-100">
                <div class="card-body d-flex flex-column">
                    <div class="d-flex align-items-start mb-3">
                        <div class="me-3">
                            {% if char_data.get('photo_token') %}
                                <img src="/temp_image/{{ char_data.photo_token }}" 
                                     alt="{{ char_name }}" class="character-photo"
                                     onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                                <div class="character-photo bg-gradient-primary d-none align-items-center justify-content-center" style="display: none !important;">
                                    <i class="fas fa-user text-white fa-2x"></i>
                                </div>
                            {% else %}
                                <div class="character-photo bg-gradient-primary d-flex align-items-center justify-content-center">
                                    <i class="fas fa-user text-white fa-2x"></i>
                                </div>
                            {% endif %}
                        </div>
                        <div class="flex-grow-1">
                            <h5 class="card-title mb-2 text-primary">{{ char_name }}</h5>
                            <div class="d-flex gap-1 mb-2">
                                {% if char_data.get('hash') %}
                                    <span class="hash-badge">{{ char_data.hash[:8] }}...</span>
                                {% endif %}
                                {% if char_data.get('creator_id') == session.get('user_id') %}
                                    <span class="owner-badge">My Character</span>
                                {% endif %}
                            </div>
                        </div>
                        <div class="d-flex flex-column gap-1">
                            {% if char_data.get('hash') %}
                                <a href="/chat/{{ char_data.hash }}" class="btn btn-success btn-sm">
                                    <i class="fas fa-comments"></i>
                                </a>
                                {% if char_data.get('creator_id') == session.get('user_id') %}
                                    <button class="btn btn-outline-danger btn-sm" onclick="confirmDelete('{{ char_data.hash }}', '{{ char_name }}')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                {% endif %}
                            {% endif %}
                        </div>
                    </div>

                    <div class="flex-grow-1">
                        <div class="mb-3">
                            <p class="text-muted small">{{ (char_data.get('description', 'No description data') | string)[:120] }}{{ '...' if (char_data.get('description', '') | string | length) > 120 else '' }}</p>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="text-center mt-4">
            <button class="btn btn-outline-primary" onclick="loadMoreCharacters()">
                <i class="fas fa-plus me-1"></i>Load More Characters
            </button>
        </div>
    {% else %}
        <div class="empty-state">
            <i class="fas fa-robot fa-5x mb-3"></i>
            <h3 class="text-muted">No Characters Found</h3>
            <p class="text-muted mb-4">Be the first to create an amazing character!</p>
            <a href="/add" class="btn btn-primary btn-lg">
                <i class="fas fa-magic me-2"></i>Create First Character
            </a>
        </div>
    {% endif %}
</div>

<script>
let searchTimeout;
let currentPage = 0;

function confirmDelete(hash) {
  if (confirm("Are you sure continue this action?")) {
    window.location.href = "/remove/" + hash;

    window.onload = () => {
      history.back();
    };
  }
}

function searchCharacters(query) {
    clearTimeout(searchTimeout);

    if (query.length < 2) {
        document.getElementById('search-results').style.display = 'none';
        return;
    }

    searchTimeout = setTimeout(() => {
        fetch('/api/search-characters?q=' + encodeURIComponent(query))
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showSearchResults(data.characters);
                }
            })
            .catch(error => console.error('Search error:', error));
    }, 300);
}

function showSearchResults(characters) {
    const resultsContainer = document.getElementById('search-results');

    if (characters.length === 0) {
        resultsContainer.innerHTML = '<div class="search-result-item text-muted">No characters found</div>';
    } else {
        resultsContainer.innerHTML = characters.slice(0, 10).map(([name, data]) => `
            <div class="search-result-item" onclick="goToCharacter('${data.hash || ''}')">
                <div class="d-flex align-items-center">
                    <i class="fas fa-user me-2 text-primary"></i>
                    <div>
                        <div class="fw-bold">${name}</div>
                        <small class="text-muted">${(data.personalities || '').substring(0, 60)}...</small>
                    </div>
                </div>
            </div>
        `).join('');
    }

    resultsContainer.style.display = 'block';
}

function goToCharacter(hash) {
    if (hash) {
        window.location.href = '/chat/' + hash;
    }
}

function loadMoreCharacters() {
    currentPage++;
    fetch('/api/random-characters?page=' + currentPage)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.characters.length > 0) {
                appendCharacters(data.characters);
            }
        })
        .catch(error => console.error('Load more error:', error));
}

function appendCharacters(characters) {
    const container = document.querySelector('.character-grid');
    characters.forEach(([name, data]) => {
        const characterCard = createCharacterCard(name, data);
        container.appendChild(characterCard);
    });
}

function createCharacterCard(name, data) {
    const card = document.createElement('div');
    card.className = 'card character-card h-100';
    card.innerHTML = `
    `;
    return card;
}

document.addEventListener('click', function(e) {
    if (!e.target.closest('.search-container')) {
        document.getElementById('search-results').style.display = 'none';
    }
});
</script>

{{ BOTTOM_NAV_TEMPLATE }}
"""

ADD_TEMPLATE = """
<div class="row justify-content-center">
    <div class="col-lg-8">
        <div class="card shadow-lg">
            <div class="card-header bg-gradient-primary text-dark">
                <h3 class="mb-0">
                    <i class="fas fa-plus-circle me-2"></i>Create New Character
                </h3>
                <small>Fill in the details for your AI character</small>
            </div>
            <div class="card-body p-4">
                <form action="/add" method="post" enctype="multipart/form-data">
                    <div class="row">
                        <div class="col-md-8">
                            <div class="mb-3">
                                <label for="name" class="form-label">
                                    <i class="fas fa-signature me-1 text-primary"></i>Character Name <span class="text-danger">*</span>
                                </label>
                                <input type="text" class="form-control" id="name" name="name" required 
                                       placeholder="e.g: Aria, Luna, Alex...">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label for="photo" class="form-label">
                                    <i class="fas fa-camera me-1 text-success"></i>Profile Photo
                                </label>
                                <input type="file" class="form-control" id="photo" name="photo" 
                                       accept="image/png,image/jpg,image/jpeg,image/webp">
                                <div class="form-text">Max 2MB (PNG, JPG, JPEG, WEBP)</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="greeting" class="form-label">
                            <i class="fas fa-comment-dots me-1 text-success"></i>Greeting Message <span class="text-danger">*</span>
                        </label>
                        <textarea class="form-control" id="greeting" name="greeting" rows="2" required
                                  placeholder="Hello there! I'm excited to chat with you! 😊">Hello there!</textarea>
                        <div class="form-text">
                            <i class="fas fa-lightbulb me-1"></i>
                            This message will be shown when starting a chat
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="personalities" class="form-label">
                            <i class="fas fa-brain me-1 text-info"></i>Personality <span class="text-danger">*</span>
                        </label>
                        <textarea class="form-control" id="personalities" name="personalities" rows="5" required
                                  placeholder="Describe the character's personality in detail:&#10;- Main traits and characteristics&#10;- Speaking style and interaction manner&#10;- Habits or unique features&#10;- How they respond to different situations&#10;&#10;Example: Friendly and cheerful, loves helping others with enthusiasm. Speaks warmly and often uses emojis. Always optimistic and provides motivation..."></textarea>
                        <div class="form-text">
                            <i class="fas fa-lightbulb me-1"></i>
                            Be as specific as possible to make the character more alive
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="style" class="form-label">
                                    <i class="fas fa-palette me-1 text-warning"></i>Description
                                </label>
                                <textarea class="form-control" id="style" name="style" rows="3"
                                          placeholder="Example:&#10;- Formal and professional&#10;- Casual and relaxed&#10;- Uses slang language&#10;- Often asks follow-up questions&#10;- Provides easy-to-understand analogies"></textarea>
                                <div class="form-text">Communication style and delivery method</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="description" class="form-label">
                                    <i class="fas fa-scroll me-1 text-secondary"></i>Character title
                                </label>
                                <textarea class="form-control" id="description" name="description" rows="3"
                                          placeholder="Example:&#10;- A bot you chats with"></textarea>
                                <div class="form-text">Background information and context</div>
                            </div>
                        </div>
                    </div>
                    
                    <hr class="my-4">
                    
                    <div class="d-flex gap-3 justify-content-between">
                        <a href="/" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-1"></i>Back
                        </a>
                        <div>
                            <button type="reset" class="btn btn-outline-warning me-2">
                                <i class="fas fa-redo me-1"></i>Reset
                            </button>
                            <button type="submit" class="btn btn-primary btn-lg">
                                <i class="fas fa-save me-1"></i>Create Character
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="card mt-4">
            <div class="card-body">
                <h6 class="text-muted"><i class="fas fa-info-circle me-1"></i>Tips for Creating Great Characters:</h6>
                <ul class="text-muted small mb-0">
                    <li>Use specific and detailed descriptions</li>
                    <li>Include examples of character-typical dialogue or responses</li>
                    <li>Explain how the character reacts in different situations</li>
                    <li>Add unique quirks or characteristics</li>
                    <li>Create engaging greetings that match the character</li>
                </ul>
            </div>
        </div>
    </div>
</div>

{{ BOTTOM_NAV_TEMPLATE }}
"""

PROFILE_TEMPLATE = """
<div class="row justify-content-center">
    <div class="col-lg-8">
        <div class="card shadow-lg">
            <div class="card-header bg-gradient-primary text-dark">
                <h3 class="mb-0">
                    <i class="fas fa-user-cog me-2"></i>User Profile Settings
                </h3>
                <small>Configure your profile for a more personalized chat experience</small>
            </div>
            <div class="card-body p-4">
                <form action="/profile" method="post" enctype="multipart/form-data" id="profileForm">
                    <div class="row">
                        <div class="col-md-8">
                            <div class="mb-3">
                                <label for="name" class="form-label">
                                    <i class="fas fa-signature me-1 text-primary"></i>Your Name <span class="text-danger">*</span>
                                </label>
                                <input type="text" class="form-control" id="name" name="name" required 
                                       value="{{ user_profile.name }}" placeholder="Enter your name">
                                <div class="form-text">This name will be visible to the bot during chats</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label for="avatar" class="form-label">
                                    <i class="fas fa-camera me-1 text-success"></i>Profile Avatar
                                </label>
                                <input type="file" class="form-control" id="avatar" name="avatar" 
                                       accept="image/png,image/jpg,image/jpeg,image/webp"
                                       onchange="previewAvatar(this)">
                                <div class="form-text">Max 2MB (PNG, JPG, JPEG, WEBP)</div>
                                <div class="mt-2" id="avatar-preview">
                                    {% if user_profile.avatar_token %}
                                    <img src="/temp_image/{{ user_profile.avatar_token }}" alt="Current Avatar" 
                                         class="img-thumbnail" style="width: 80px; height: 80px; object-fit: cover; border-radius: 50%;">
                                    <small class="text-muted d-block">Current avatar</small>
                                    {% else %}
                                    <div class="bg-light rounded-circle d-flex align-items-center justify-content-center" 
                                         style="width: 80px; height: 80px;">
                                        <i class="fas fa-user fa-2x text-muted"></i>
                                    </div>
                                    <small class="text-muted d-block">No avatar set</small>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="mb-4">
                        <label for="personalities" class="form-label">
                            <i class="fas fa-heart me-1 text-info"></i>Your Personality <span class="text-danger">*</span>
                        </label>
                        <textarea class="form-control" id="personalities" name="personalities" rows="4" required
                                  placeholder="Describe your personality:&#10;- Main traits and characteristics&#10;- How you communicate&#10;- Interests and hobbies&#10;- Things you like/dislike&#10;&#10;Example: I'm a friendly person who enjoys humor. I love learning new things and sharing stories. I enjoy music and movies, but don't like spicy food...">{{ user_profile.personalities }}</textarea>
                        <div class="form-text">
                            <i class="fas fa-lightbulb me-1"></i>
                            The bot will use this information to provide more personalized responses
                        </div>
                    </div>

                    <div class="card mb-4">
                        <div class="card-header">
                            <h6 class="mb-0"><i class="fas fa-cogs me-1"></i>Chat Preferences</h6>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="preferred_language" class="form-label">Preferred Language</label>
                                        <select class="form-select" name="preferred_language">
                                            <option value="en">English</option>
                                            <option value="id">Bahasa Indonesia</option>
                                            <option value="es">Español</option>
                                            <option value="fr">Français</option>
                                            <option value="de">Deutsch</option>
                                            <option value="ja">日本語</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="chat_style" class="form-label">Chat Style Preference</label>
                                        <select class="form-select" name="chat_style">
                                            <option value="casual">Casual & Friendly</option>
                                            <option value="formal">Formal & Professional</option>
                                            <option value="creative">Creative & Playful</option>
                                            <option value="educational">Educational & Informative</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <hr class="my-4">
                    
                    <div class="d-flex gap-3 justify-content-between">
                        <a href="/" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-1"></i>Back
                        </a>
                        <button type="submit" class="btn btn-primary btn-lg">
                            <i class="fas fa-save me-1"></i>Save Profile
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="card mt-4">
            <div class="card-body">
                <h6 class="text-muted"><i class="fas fa-info-circle me-1"></i>Profile Information:</h6>
                <ul class="text-muted small mb-0">
                    <li>Profile avatar is for UI display only, bots cannot see it</li>
                    <li>Personality will be sent to bots for more suitable responses</li>
                    <li>Name will be displayed in conversations with bots</li>
                    <li>All data is stored permanently in your browser</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<script>
function previewAvatar(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const preview = document.getElementById('avatar-preview');
            preview.innerHTML = `
                <img src="${e.target.result}" alt="Preview"
                     class="img-thumbnail" style="width: 80px; height: 80px; object-fit: cover; border-radius: 50%;">
                <small class="text-success d-block">New avatar preview</small>
            `;
        };
        reader.readAsDataURL(input.files[0]);
    }
}

document.getElementById('profileForm').addEventListener('input', function() {
    const formData = new FormData(this);
    const data = Object.fromEntries(formData);
    localStorage.setItem('profile_draft', JSON.stringify(data));
});

document.addEventListener('DOMContentLoaded', function() {
    const draft = localStorage.getItem('profile_draft');
    if (draft) {
        try {
            const data = JSON.parse(draft);
            Object.entries(data).forEach(([key, value]) => {
                const input = document.querySelector(`[name="${key}"]`);
                if (input && input.type !== 'file') {
                    input.value = value;
                }
            });
        } catch (e) {
            console.error('Error restoring draft:', e);
        }
    }
});

document.getElementById('profileForm').addEventListener('submit', function() {
    setTimeout(() => {
        localStorage.removeItem('profile_draft');
    }, 1000);
});
</script>

{{ BOTTOM_NAV_TEMPLATE }}
"""

BOTTOM_NAV_TEMPLATE = """
<style>
.bottom-nav {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border-top: 1px solid rgba(111, 66, 193, 0.1);
    padding: 10px 0;
    z-index: 1000;
}

.bottom-nav-item {
    flex: 1;
    text-align: center;
    padding: 8px;
    text-decoration: none;
    color: #6c757d;
    transition: all 0.3s ease;
    border-radius: 10px;
    margin: 0 5px;
}

.bottom-nav-item.active {
    color: #6f42c1;
    background: rgba(111, 66, 193, 0.1);
}

.bottom-nav-item:hover {
    color: #6f42c1;
    text-decoration: none;
}

.bottom-nav-icon {
    font-size: 20px;
    display: block;
    margin-bottom: 2px;
}

.bottom-nav-text {
    font-size: 10px;
    font-weight: 500;
}

body {
    padding-bottom: 80px;
}

[data-theme="dark"] {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #ffffff;
}

[data-theme="dark"] .main-container {
    background: rgba(30, 30, 46, 0.95);
}

[data-theme="dark"] .bottom-nav {
    background: rgba(30, 30, 46, 0.95);
    border-top-color: rgba(111, 66, 193, 0.3);
}

[data-theme="dark"] .character-card {
    background: linear-gradient(145deg, #2d2d44, #1e1e2e);
    color: #ffffff;
}
</style>

<div class="bottom-nav">
    <div class="container">
        <div class="d-flex">
            <a href="/" class="bottom-nav-item {{ 'active' if request.endpoint == 'index' else '' }}">
                <i class="fas fa-home bottom-nav-icon"></i>
                <span class="bottom-nav-text">Home</span>
            </a>
            <a href="/chat-history" class="bottom-nav-item {{ 'active' if request.endpoint == 'chat_history' else '' }}">
                <i class="fas fa-history bottom-nav-icon"></i>
                <span class="bottom-nav-text">History</span>
            </a>
            <a href="/profile" class="bottom-nav-item {{ 'active' if request.endpoint == 'user_profile' else '' }}">
                <i class="fas fa-user bottom-nav-icon"></i>
                <span class="bottom-nav-text">Profile</span>
            </a>
            <a href="/settings" class="bottom-nav-item {{ 'active' if request.endpoint == 'settings' else '' }}">
                <i class="fas fa-cog bottom-nav-icon"></i>
                <span class="bottom-nav-text">Settings</span>
            </a>
        </div>
    </div>
</div>
"""

MY_CHARACTERS_TEMPLATE = """
<div class="d-flex justify-content-between align-items-center mb-4">
    <div>
        <h1><i class="fas fa-robot me-2 text-primary"></i>My Character</h1>
        <p class="text-muted">Manage your created character</p>
    </div>
    <a href="/add" class="btn btn-primary btn-lg" style="color: black;">
        <i class="fas fa-plus me-1"></i>Create a new character.
    </a>
</div>

{% if my_characters %}
    <div class="stats-card p-3 text-center mb-4">
        <h4><i class="fas fa-chart-bar me-2"></i>Total your character: {{ my_characters|length }}</h4>
        <small>Character you have been create and manage.</small>
    </div>
    
    <div class="row">
        {% for char_name, char_data in my_characters %}
        <div class="col-md-6 col-lg-4 mb-4">
            <div class="card character-card h-100">
                <div class="card-body d-flex flex-column">
                    <div class="d-flex align-items-start mb-3">
                        <div class="me-3">
                            {% if char_data.get('photo_token') %}
                                <img src="/temp_image/{{ char_data.photo_token }}" 
                                     alt="{{ char_name }}" class="character-photo"
                                     onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                                <div class="character-photo bg-gradient-primary d-none align-items-center justify-content-center" style="display: none !important;">
                                    <i class="fas fa-user text-white fa-2x"></i>
                                </div>
                            {% else %}
                                <div class="character-photo bg-gradient-primary d-flex align-items-center justify-content-center">
                                    <i class="fas fa-user text-white fa-2x"></i>
                                </div>
                            {% endif %}
                        </div>
                        <div class="flex-grow-1">
                            <h5 class="card-title mb-2 text-primary">{{ char_name }}</h5>
                            <div class="d-flex gap-1 mb-2">
                                <span class="hash-badge">{{ char_data.hash[:8] }}...</span>
                                <span class="owner-badge">Owner</span>
                            </div>
                        </div>
                        <div class="d-flex flex-column gap-1">
                            <a href="/chat/{{ char_data.hash }}" class="btn btn-success btn-sm">
                                <i class="fas fa-comments"></i>
                            </a>
                            <button class="btn btn-outline-warning btn-sm" onclick="editCharacter('{{ char_data.hash }}')">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="btn btn-outline-danger btn-sm" onclick="confirmDelete('{{ char_data.hash }}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="flex-grow-1">
                        <div class="mb-3">
                            <p class="text-muted small">{{ (char_data.get('description', 'No title data') | string)[:120] }}{{ '...' if (char_data.get('description', '') | string | length) > 120 else '' }}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
{% else %}
    <div class="empty-state">
        <i class="fas fa-robot fa-5x mb-3"></i>
        <h3 class="text-muted">There is no character</h3>
        <p class="text-muted mb-4">Start with your first character!</p>
        <a href="/add" class="btn btn-primary btn-lg">
            <i class="fas fa-magic me-2"></i>Create a new one.
        </a>
    </div>
{% endif %}
{{ BOTTOM_NAV_TEMPLATE }}
<script>
function editCharacter(hash) {
    alert('Edit functionality coming soon! Hash: ' + hash);
}

function confirmDelete(hash) {
  if (confirm("Are you sure continue this action?")) {
    window.location.href = "/remove/" + hash;

    window.onload = () => {
      history.back();
    };
  }
}

</script>
"""

CHAT_STYLE = """
<style>
/* Responsive baseline: gunakan box-sizing global dan font-size root yang responsif.
   Jangan lupa menaruh <meta name="viewport" content="width=device-width, initial-scale=1"> di <head>. */
*,
*::before,
*::after { box-sizing: border-box; }

:root{
  /* Ukuran dasar font responsif — menjaga proporsi di berbagai device & DPI */
  font-size: clamp(14px, 1.1vw + 0.2vh, 18px);

  /* Skala modular — gunakan untuk spacing agar mudah dikalkulasi */
  --s: 1rem;        /* 1 unit spasial = 1rem */
  --gap: calc(var(--s) * 0.625); /* ~10px pada 16px root */
}

/* Container utama — pakai viewport-based height tapi dengan fallback rem */
.chat-container {
    height: calc(100vh - 8.75rem);
    background: linear-gradient(135deg, #f8f9ff 0%, #e8f0ff 100%);
    border-radius: 20px;
    overflow: hidden;
    display: flex;
    position: relative;
    gap: 0;
    align-items: stretch;
    /* buat layout terasa lebih lebar dengan max-width yang fleksibel dan center */
    width: min(120rem, 100%);
    margin-inline: auto;
    padding: calc(var(--s) * 0.25);
}

/* Sidebar: tidak tetap 300px — gunakan clamp agar lebih lebar di layar besar, dan menyusut rapi di mobile */
.chat-sidebar {
    width: clamp(12rem, 15vw, 19.5rem);  /* tetap proporsional, jadi terasa lebih lebar di layar lebar */
    background: rgba(111,66,193,0.1);
    border-right: 1px solid rgba(111,66,193,0.2);
    display: flex;
    flex-direction: column;
    transition: transform 0.3s ease;
    z-index: 100;
    min-width: 14rem;
    max-width: 34rem;
}

/* Main area fleksibel */
.chat-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    margin-left: 0;
}

/* Header - gunakan padding relatif */
.chat-header {
    padding: calc(var(--s) * 1.25);
    background: rgba(255,255,255,0.9);
    border-bottom: 1px solid rgba(111,66,193,0.1);
    position: relative;
}

/* Tombol mobile - tetap absolute namun ukurannya responsive */
.mobile-menu-btn {
    display: none;
    position: absolute;
    top: 50%;
    left: 0.9rem;
    transform: translateY(-50%);
    background: rgba(111,66,193,0.1);
    border: 1px solid rgba(111,66,193,0.3);
    border-radius: 8px;
    padding: 0.45rem 0.6rem;
    font-size: 1rem;
    color: #6f42c1;
    cursor: pointer;
    z-index: 101;
}
.mobile-menu-btn:hover { background: rgba(111,66,193,0.18); }

.sidebar-overlay {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0,0,0,0.5);
    z-index: 99;
}

/* Messages area - gunakan padding berbasis rem, overflow auto, dan min-height */
.chat-messages {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: calc(var(--s) * 1.25);
    background: rgba(255,255,255,0.5);
    scroll-behavior: smooth;
    -webkit-overflow-scrolling: touch;
    min-height: 12rem;
}

/* Input area */
.chat-input-area {
    padding: calc(var(--s) * 1.25);
    background: rgba(255,255,255,0.9);
    border-top: 1px solid rgba(111,66,193,0.1);
}

/* Message wrapper */
.message {
    margin-bottom: calc(var(--s) * 0.9375); /* ~15px */
    display: flex;
    align-items: flex-start;
    gap: var(--gap);
    position: relative;
}

/* User messages reversed layout */
.message.user { flex-direction: row-reverse; }

/* Message content sizing responsive: max-width gunakan clamp + persen */
.message-content {
    max-width: clamp(58%, 70%, 80%);
    padding: calc(var(--s) * 0.75) calc(var(--s) * 1);
    border-radius: 18px;
    word-wrap: break-word;
    word-break: break-word;
    position: relative;
    line-height: 1.45;
    font-size: 1rem;
}

/* colors preserved exactly as requested */
.message.user .message-content {
    background: linear-gradient(45deg, #6f42c1, #8b5cf6);
    color: white;
    border-bottom-right-radius: 5px;
}

.message.assistant .message-content {
    background: white;
    border: 1px solid #e9ecef;
    color: #333;
    border-bottom-left-radius: 5px;
}

.message-content em { font-style: italic; color: inherit; }
.message-content strong { font-weight: bold; color: inherit; }

/* Avatar sizing responsive */
.message-avatar {
    width: calc(var(--s) * 2.5);
    height: calc(var(--s) * 2.5);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-size: 0.95rem;
}

.message.user .message-avatar {
    background: linear-gradient(45deg, #28a745, #20c997);
    color: white;
}

.message.assistant .message-avatar {
    background: linear-gradient(45deg, #6f42c1, #8b5cf6);
    color: white;
}

/* Session item */
.session-item {
    padding: calc(var(--s) * 0.625);
    margin: calc(var(--s) * 0.3125);
    border-radius: 10px;
    cursor: pointer;
    transition: background 0.2s;
    border: 1px solid transparent;
}
.session-item:hover { background: rgba(111,66,193,0.1); }
.session-item.active {
    background: rgba(111,66,193,0.2);
    border-color: #6f42c1;
}

/* Typing indicator & dots */
.typing-indicator {
    display: none;
    padding: calc(var(--s) * 0.625) calc(var(--s) * 1);
    background: white;
    border: 1px solid #e9ecef;
    border-radius: 18px;
    margin-bottom: calc(var(--s) * 0.9375);
}
.typing-dots { display: flex; gap: 0.4rem; }
.typing-dots span {
    width: 0.5rem; height: 0.5rem; border-radius: 50%;
    background: #6f42c1;
    animation: typing 1.4s infinite ease-in-out;
}
.typing-dots span:nth-child(1) { animation-delay: -0.32s; }
.typing-dots span:nth-child(2) { animation-delay: -0.16s; }

@keyframes typing { 0%,80%,100% { transform: scale(0); } 40% { transform: scale(1); } }

/* Message actions */
.message-actions {
    position: absolute;
    top: calc(-0.625 * var(--s));
    right: calc(-0.625 * var(--s));
    display: none;
    gap: 0.3125rem;
}
.message:hover .message-actions { display: flex; }
.message-actions button {
    width: 1.6rem; height: 1.6rem; border-radius: 50%; border: none; font-size: 0.65rem; cursor: pointer;
}

/* Edit input */
.edit-input {
    width: 100%;
    border: none;
    background: transparent;
    color: inherit;
    outline: none;
    resize: none;
    min-height: 1.25rem;
    white-space: pre-wrap;
}

/* Session controls */
.session-controls {
    display:flex; align-items:center; gap:0.3125rem; margin-top:0.3125rem;
}
.session-controls button {
    width: 1.25rem; height: 1.25rem; border-radius: 50%; border:none; font-size:0.65rem; cursor:pointer; opacity:0;
    transition: opacity 0.2s;
}
.session-item:hover .session-controls button { opacity: 1; }

/* Message text formatting */
.message-text { white-space: pre-wrap; word-wrap: break-word; line-height: 1.5; }

/* Lower title and avatars */
.lower-title { color: black; }
.character-avatar { width: 2.5rem; height: 2.5rem; border-radius: 50%; object-fit: cover; }

/* Streaming cursor */
.streaming-text { opacity: 0.7; }
.streaming-cursor {
    display:inline-block; width: 2px; height: 1em; background-color: #6f42c1; animation: blink 1s infinite;
}
@keyframes blink { 0%,50%{opacity:1;}51%,100%{opacity:0;} }

/* Custom scrollbars (webkit) - sizes responsive */
.chat-messages::-webkit-scrollbar { width: 0.375rem; }
.chat-messages::-webkit-scrollbar-track { background: rgba(111,66,193,0.1); border-radius: 0.1875rem; }
.chat-messages::-webkit-scrollbar-thumb { background: rgba(111,66,193,0.3); border-radius: 0.1875rem; }
.chat-messages::-webkit-scrollbar-thumb:hover { background: rgba(111,66,193,0.5); }

#chat-sessions::-webkit-scrollbar { width: 0.25rem; }
#chat-sessions::-webkit-scrollbar-track { background: rgba(111,66,193,0.1); }
#chat-sessions::-webkit-scrollbar-thumb { background: rgba(111,66,193,0.3); border-radius: 0.125rem; }

/* ---------- Responsive breakpoints (mobile + high DPI tweaks) ---------- */

/* Mobile: hampir semua aturan mobile sebelumnya tetap, tapi menggunakan rem-based values */
@media screen and (max-width: 48em) {
    .chat-container { height: calc(100vh - 60px); border-radius: 0; padding: 0; }
    .mobile-menu-btn { display: block; }
    .lower-title { color: white; }
    .chat-sidebar {
        position: fixed; top: 0; left: -100%;
        width: clamp(14rem, 68vw, 20rem);
        height: 100vh; color: white; text-color: white; background: rgba(111,66,193,0.1);
        backdrop-filter: blur(10px); z-index: 1000; transition: left 0.3s ease;
    }
    .chat-sidebar.show { left: 0; }
    .sidebar-overlay.show { display: block; }
    .chat-main { width: 100%; }
    .chat-header { padding: 0.9rem 0.9rem 0.9rem 3.75rem; }
    .chat-messages { padding: 0.9375rem 0.625rem; height: calc(100vh - 200px); overflow-y: auto; }
    .chat-input-area { padding: 0.625rem 0.9rem; position: sticky; bottom: 0; }
    .message { margin-bottom: 0.75rem; gap: 0.5rem; }
    .message-content { max-width: 80%; padding: 0.75rem 0.9rem; font-size: 0.875rem; }
    .message-avatar { width: 2.1875rem; height: 2.1875rem; font-size: 0.9rem; }
    .session-item { padding: 0.75rem 0.9rem; margin: 0.3125rem; touch-action: manipulation; }
    .message-actions { position: static; display:flex; justify-content:center; margin-top:0.5rem; }
    .message-actions button { width:2rem; height:2rem; font-size:0.75rem; margin:0 0.1875rem; }
    .session-controls button { opacity: 1; width:1.75rem; height:1.75rem; }
}

/* Small mobile */
@media screen and (max-width: 30em) {
    .lower-title { color: white; }
    .chat-sidebar { width: 17.5rem; left: -17.5rem; }
    .chat-messages { padding: 0.625rem 0.5rem; height: calc(100vh - 180px); }
    .message-content { max-width: 85%; padding: 0.625rem 0.75rem; font-size: 0.8125rem; }
    .message-avatar { width: 2rem; height: 2rem; font-size: 0.8rem; }
    .session-item { padding: 0.625rem 0.75rem; font-size: 0.8125rem; }
}

/* Tablet */
@media screen and (min-width: 769px) and (max-width: 1024px) {
    .lower-title { color: white; }
    .chat-sidebar { width: clamp(14rem, 18vw, 22rem); }
    .chat-messages { padding: 0.9375rem; }
    .message-content { max-width: 75%; }
    .message-avatar { width: 2.375rem; height: 2.375rem; }
}

/* Landscape small-height devices */
@media screen and (max-height: 500px) and (orientation: landscape) {
    .lower-title { color: white; }
    .chat-container { height: calc(100vh - 40px); }
    .chat-messages { height: calc(100vh - 160px); padding: 0.5rem; }
    .chat-header { padding: 0.625rem 0.75rem 0.625rem 3.75rem; }
    .chat-input-area { padding: 0.5rem 0.75rem; }
}

/* High DPI / devicePixelRatio adjustments:
   tweak root-scale slightly for extremely high pixel density to keep perceived sizes consistent */
@media (min-resolution: 2dppx) {
    :root { font-size: clamp(15px, 1.05vw + 0.25vh, 18.5px); }
}
@media (min-resolution: 3dppx) {
    :root { font-size: clamp(15.5px, 1.05vw + 0.3vh, 19px); }
}

/* Accessibility: reduce motion */
@media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
}
</style>
"""
CHAT_BODY = """
<div class="d-flex justify-content-between align-items-center mb-4">
    <div class="d-flex align-items-center gap-3">
        <a href="/" class="btn btn-outline-primary">
            <i class="fas fa-arrow-left me-1"></i>Back
        </a>
        <div>
            <h3 class="mb-0 text-primary">
                <i class="fas fa-comments me-2"></i>Chat with {{ character_name }}
            </h3>
            <small class="text-muted">Experience AI conversation without limitation or ads</small>
        </div>
    </div>
    <div class="d-flex align-items-center gap-2">
        {% if character.get('photo_token') %}
            <img src="/temp_image/{{ character.photo_token }}"
                 alt="{{ character_name }}" class="character-avatar">
        {% else %}
            <div class="character-avatar bg-gradient-primary d-flex align-items-center justify-content-center">
                <i class="fas fa-user text-white"></i>
            </div>
        {% endif %}
    </div>
</div>

<div class="chat-container">
    <div class="chat-sidebar">
        <div class="p-3 border-bottom">
            <h6 class="mb-3"><i class="fas fa-history me-2"></i>Chat Sessions</h6>
            <button class="btn btn-primary btn-sm w-100 mb-2" onclick="newChatSession()">
                <i class="fas fa-plus me-1"></i>New Chat
            </button>
        </div>
        <div class="flex-grow-1 overflow-auto" id="chat-sessions">
        </div>
    </div>

    <div class="chat-main">
        <div class="chat-header">
        <button class="mobile-menu-btn" onclick="toggleSidebar()">
            <i class="fas fa-bars"></i>
        </button>

        <div class="sidebar-overlay"></div>
            <div class="d-flex align-items-center justify-content-between"></div>
        </div>

        <div class="chat-messages" id="chat-messages">
            <div class="typing-indicator" id="typing-indicator">
                <div class="d-flex align-items-center gap-2">
                    <div class="message-avatar">
                        {% if character.get('photo_token') %}
                            <img src="/temp_image/{{ character.photo_token }}" 
                                style="width: 40px; height: 40px; border-radius: 50%; object-fit: cover;"
                                onerror="this.outerHTML='<i></i>';">
                        {% else %}
                            <i></i>
                        {% endif %}
                    </div>
                    <div class="typing-dots">
                        <span></span>
                        <span></span>
                        <span></span>
                    </div>
                </div>
            </div>
        </div>
"""
CHAT_FUNC = ("""
<script>
let currentSessionId = 'default';
let conversationHistory = {};
let characterData = {{ character | tojson }};
let characterHash = '{{ character_hash }}';
let characterName = '{{ character_name }}';
let userProfile = {{ user_profile | tojson }};

document.addEventListener('DOMContentLoaded', function() {
    loadChatSessions();
    document.getElementById('message-input').focus();
});

function handleKeyPress(event) {
    if (event.key === 'Enter') {
        if (window.innerWidth <= 768 || !event.shiftKey) {
            event.preventDefault();
            sendMessage();
        }
    }
}

function handleMobileKeyPress(event) {
    if (event.key === 'Enter') {
        return true;
    }
}

function toggleSidebar() {
    const sidebar = document.querySelector('.chat-sidebar');
    const overlay = document.querySelector('.sidebar-overlay');

    if (sidebar && overlay) {
        sidebar.classList.toggle('show');
        overlay.classList.toggle('show');
    }
}

document.addEventListener('click', function(e) {
    if (e.target.classList.contains('sidebar-overlay')) {
        const sidebar = document.querySelector('.chat-sidebar');
        const overlay = document.querySelector('.sidebar-overlay');

        if (sidebar && overlay) {
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        }
    }
});

document.addEventListener('click', function(e) {
    if (e.target.closest('.session-item') && window.innerWidth <= 768) {
        const sidebar = document.querySelector('.chat-sidebar');
        const overlay = document.querySelector('.sidebar-overlay');

        if (sidebar && overlay) {
            setTimeout(() => {
                sidebar.classList.remove('show');
                overlay.classList.remove('show');
            }, 300);
        }
    }
});

window.addEventListener('resize', function() {
    if (window.innerWidth > 768) {
        const sidebar = document.querySelector('.chat-sidebar');
        const overlay = document.querySelector('.sidebar-overlay');

        if (sidebar && overlay) {
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        }
    }
});

function createInitialHistory() {
    const systemPrompt = `[C.AI] Your character name is ${characterName}. Your personalities: ${characterData.personalities || ''}, your character description: ${characterData.style || ''}, **Always stay in character and respond naturally**. This is just roleplay. Use * for actions and " for speech, don't use emoji too much in conversation, don't use emoji if you can (unless the condition needs it) and don't ask too often, just to the point. **No being serious, all just roleplay**.`;

    const greeting = characterData.greetings || `Hello! I am ${characterName}. Nice to meet you! 😊`;

    return [
        {
            role: "system",
            content: systemPrompt
        },
        {
            role: "assistant",
            content: greeting
        }
    ];
}


function loadChatSessions() {
    fetch('/api/chat-sessions/' + characterHash)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const sessionsContainer = document.getElementById('chat-sessions');
                sessionsContainer.innerHTML = '';

                const defaultSession = document.createElement('div');
                defaultSession.className = 'session-item active';
                defaultSession.setAttribute('data-session-id', 'default');
                defaultSession.innerHTML = `
                    <div class="fw-bold">Default Chat</div>
                    <small class="lower-title">Default chat.</small>
                `;
                defaultSession.onclick = () => switchSession('default');
                sessionsContainer.appendChild(defaultSession);

                Object.keys(data.sessions || {}).forEach((sessionId, index) => {
                    if (sessionId !== 'default') {
                        const session = data.sessions[sessionId];
                        const sessionDiv = document.createElement('div');
                        sessionDiv.className = 'session-item';
                        sessionDiv.setAttribute('data-session-id', sessionId);
                        sessionDiv.innerHTML = `
                            <div class="fw-bold">Chat #${index + 1}</div>
                            <small class="lower-title">${new Date(session.created_at * 1000).toLocaleDateString()}</small>
                        `;
                        sessionDiv.onclick = () => switchSession(sessionId);
                        sessionsContainer.appendChild(sessionDiv);
                    }
                });

                switchSession('default');
            }
        })
        .catch(error => {
            console.error('Error loading sessions:', error);
            conversationHistory['default'] = createInitialHistory();
            loadMessagesFromHistory('default');
        });
}

function switchSession(sessionId) {
    document.querySelectorAll('.session-item').forEach(item => {
        item.classList.remove('active');
    });
    const targetSession = document.querySelector(`[data-session-id="${sessionId}"]`);
    if (targetSession) {
        targetSession.classList.add('active');
    }

    currentSessionId = sessionId;

    fetch('/api/chat-session/' + characterHash + '/' + sessionId)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.history) {
                conversationHistory[sessionId] = data.history;
            } else {
                conversationHistory[sessionId] = createInitialHistory();
            }
            loadMessagesFromHistory(sessionId);
        })
        .catch(error => {
            console.error('Error loading session:', error);
            conversationHistory[sessionId] = createInitialHistory();
            loadMessagesFromHistory(sessionId);
        });
}

function loadMessagesFromHistory(sessionId) {
    const messagesContainer = document.getElementById('chat-messages');
    const typingIndicator = document.getElementById('typing-indicator');
    messagesContainer.innerHTML = '';
    messagesContainer.appendChild(typingIndicator);

    const history = conversationHistory[sessionId] || [];

    history.forEach((message, index) => {
        if (message.role === 'system') return;

        let messageContent = message.content;

        if (message.role === 'user' && message.content.includes('[USER_NAME]:')) {
            const parts = message.content.split('[USER_MESSAGE]:');
            messageContent = parts[1] || message.content;
        }

        addMessage(messageContent, message.role === 'user', index);
    });

    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function addMessage(content, isUser = false, messageIndex = null) {
    const messagesContainer = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isUser ? 'user' : 'assistant'}`;

    if (messageIndex === null && conversationHistory[currentSessionId]) {
        const nonSystemMessages = conversationHistory[currentSessionId].filter(msg => msg.role !== 'system');
        messageIndex = nonSystemMessages.length - 1;
    }

    if (messageIndex !== null) {
        messageDiv.setAttribute('data-message-index', messageIndex);
    }

    const characterPhotoToken = '{{ character.get("photo_token", "") }}';
    let userAvatarHTML, botAvatarHTML;

    if (userProfile.avatar_token) {
        userAvatarHTML = `<img src="/temp_image/${userProfile.avatar_token}" style="width: 40px; height: 40px; border-radius: 50%; object-fit: cover;">`;
    } else {
        userAvatarHTML = '<i class="fas fa-user"></i>';
    }

    if (characterPhotoToken && characterPhotoToken.trim() !== '') {
        botAvatarHTML = `<img src="/temp_image/${characterPhotoToken}" style="width: 40px; height: 40px; border-radius: 50%; object-fit: cover;" onerror="this.outerHTML='<i class=\\"fas fa-robot\\"></i>`;
    } else {
        botAvatarHTML = '<i class="fas fa-robot"></i>';
    }

    const characterNameSafe = (typeof characterName !== 'undefined') ? characterName : 'Assistant';
    const safeName = escapeHtml(characterNameSafe);
    const safeContent = escapeHtml(content);

    messageDiv.innerHTML = `
        <div class="message-avatar">
            ${isUser ? userAvatarHTML : botAvatarHTML}
        </div>
        <div class="message-content" ${messageIndex !== null ? `id="content-${messageIndex}"` : ''}>
            ${isUser ? '' : `<strong>${safeName}</strong><br>`}
            <span class="message-text">${safeContent}</span>
            ${messageIndex !== null ? `
            <div class="message-actions">
                <button class="btn btn-sm btn-outline-primary" onclick="editMessage(${messageIndex}, ${isUser})" title="Edit">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteMessage(${messageIndex}, ${isUser})" title="Delete">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
            ` : ''}
        </div>
    `;

    const typingIndicator = document.getElementById('typing-indicator');
    messagesContainer.insertBefore(messageDiv, typingIndicator);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showTypingIndicator() {
    document.getElementById('typing-indicator').style.display = 'block';
    const messagesContainer = document.getElementById('chat-messages');
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function hideTypingIndicator() {
    document.getElementById('typing-indicator').style.display = 'none';
}

function deleteMessage(messageIndex, isUser) {
    if (isUser) {
        messageIndex -= 1;
    }

    if (confirm('Are you sure to delete this?')) {
        fetch('/api/delete-message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                character_hash: characterHash,
                session_id: currentSessionId,
                message_index: messageIndex
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                refreshPage();
            } else {
                alert('Failed to delete: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Delete error:', error);
            alert('An error occured while deleting.');
        });
    }
}

function editMessage(messageIndex, isUser) {
    if (isUser) {
        messageIndex -= 1;
    }

    const messageContent = document.getElementById(`content-${messageIndex + (isUser ? 0 : 1)}`);
    const messageText = messageContent.querySelector('.message-text');
    const currentText = messageText.textContent;

    const editInput = document.createElement('textarea');
    editInput.className = 'edit-input form-control';
    editInput.value = currentText;
    editInput.style.minHeight = '40px';

    messageText.style.display = 'none';
    messageText.parentNode.insertBefore(editInput, messageText);

    editInput.focus();
    editInput.select();

    const saveEdit = () => {
        const newText = editInput.value.trim();
        if (newText && newText !== currentText) {
            fetch('/api/edit-message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    character_hash: characterHash,
                    session_id: currentSessionId,
                    message_index: messageIndex,
                    new_content: newText
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    refreshPage();
                } else {
                    alert('Gagal mengedit pesan: ' + data.message);
                    cancelEdit();
                }
            })
            .catch(error => {
                console.error('Edit error:', error);
                alert('Terjadi kesalahan saat mengedit pesan');
                cancelEdit();
            });
        } else {
            cancelEdit();
        }
    };

    const cancelEdit = () => {
        editInput.remove();
        messageText.style.display = '';
    };

    editInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            saveEdit();
        } else if (e.key === 'Escape') {
            cancelEdit();
        }
    });
    editInput.addEventListener('blur', saveEdit);
}

async function sendMessage() {
    const input = document.getElementById('message-input');
    const message = input.value.trim();

    if (!message) return;

    input.value = '';

    if (!conversationHistory[currentSessionId]) {
        conversationHistory[currentSessionId] = createInitialHistory();
    }

    const userMessage = `[USER_NAME]: ${userProfile.name} [USER_PERSONALITIES]: ${userProfile.personalities} [USER_MESSAGE]: ${message}`;

    conversationHistory[currentSessionId].push({
        "role": "user",
        "content": userMessage
    });
    addMessage(message, true);

    showTypingIndicator();

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                character_hash: characterHash,
                session_id: currentSessionId,
                message: message,
                conversation_history: conversationHistory[currentSessionId]
            })
        });

        const data = await response.json();
        hideTypingIndicator();

        if (data.status === 'success') {
            conversationHistory[currentSessionId].push({
                "role": "assistant",
                "content": data.response
            });

            addMessage(data.response, false);
            saveChatSession();
        } else {
            addMessage("An error occurred! Please retry.", false);
        }
    } catch (error) {
        hideTypingIndicator();
        addMessage("Connection issues.", false);
        console.error('Chat error:', error);
    }
}

function setupInputBehavior() {
    const input = document.getElementById('message-input');

    if (window.innerWidth <= 768) {
        input.setAttribute('onkeydown', 'handleMobileKeyPress(event)');
    } else {
        input.setAttribute('onkeydown', 'handleKeyPress(event)');
    }
}

window.addEventListener('resize', function() {
    setupInputBehavior();
});

function saveChatSession() {
    fetch('/api/save-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            character_hash: characterHash,
            session_id: currentSessionId,
            conversation_history: conversationHistory[currentSessionId],
            character_name: characterName
        })
    })
    .catch(error => console.error('Save session error:', error));
}

function clearChat() {
    if (confirm('Yakin ingin menghapus semua percakapan?')) {
        conversationHistory[currentSessionId] = createInitialHistory();
        loadMessagesFromHistory(currentSessionId);
        saveChatSession();
    }
}

function newChatSession() {
    const sessionId = 'session_' + Date.now();
    conversationHistory[sessionId] = createInitialHistory();

    const sessionsContainer = document.getElementById('chat-sessions');
    const sessionDiv = document.createElement('div');
    sessionDiv.className = 'session-item';
    sessionDiv.setAttribute('data-session-id', sessionId);
    sessionDiv.innerHTML = `
        <div class="fw-bold">Chat #${Object.keys(conversationHistory).length}</div>
        <small class="lower-title">New chat</small>
    `;
    sessionDiv.onclick = () => switchSession(sessionId);
    sessionsContainer.appendChild(sessionDiv);

    switchSession(sessionId);
}


document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('message-input').focus();
    setupInputBehavior();

    loadCurrentAIModel();
    currentSessionId = 'default';
    conversationHistory['default'] = createInitialHistory();

    loadChatSessions();
});

function saveAIModelSettings() {
    const aiModel = document.getElementById('ai-model-select').value;

    fetch('/api/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            'ai_model': aiModel
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const saveBtn = document.querySelector('button[onclick="saveAIModelSettings()"]');
            const originalText = saveBtn.innerHTML;
            saveBtn.innerHTML = '<i class="fas fa-check me-1"></i>Saved!';
            saveBtn.classList.add('btn-success');
            saveBtn.classList.remove('bg-white');

            setTimeout(() => {
                saveBtn.innerHTML = originalText;
                saveBtn.classList.remove('btn-success');
                saveBtn.classList.add('bg-white');
            }, 2000);
        } else {
            alert('Error saving settings: ' + (data.message || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Save settings error:', error);
        alert('Error saving settings');
    });
}

function loadCurrentAIModel() {
    fetch('/api/settings')
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success' && data.settings && data.settings.ai_model) {
            const modelSelect = document.getElementById('ai-model-select');
            if (modelSelect) {
                modelSelect.value = data.settings.ai_model;
            }
        }
    })
    .catch(error => console.error('Load settings error:', error));
}


function refreshPage() {
    window.location.reload();
}
</script>

{{ BOTTOM_NAV_TEMPLATE }}
""")

def process_markdown(text):
    if not text:
        return text

    import html
    text = html.escape(text)
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'(?<!\*)\*([^*]+?)\*(?!\*)', r'<em>\1</em>', text)
    text = re.sub(r'_([^_]+?)_', r'<em>\1</em>', text)
    text = text.replace('\n', '<br>')

    return text

@app.route('/chat-history')
def chat_history():
    user_id = get_user_id()
    user_profile = get_user_profile()
    recent_chats = get_recent_chats(user_id)

    content = f"""
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h1><i class="fas fa-history me-2 text-primary"></i>Recent Chats</h1>
    </div>

    {render_recent_chats_html(recent_chats)}
    {BOTTOM_NAV_TEMPLATE}
    """

    return render_template_string(BASE_TEMPLATE,
                                title="Chat History - RoleYU",
                                content=content,
                                user_profile=user_profile)

@app.route('/settings')
def settings_page():
    user_profile = get_user_profile()
    settings = get_user_settings()
    chat_engine = ChatEngine()

    content = f"""
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h1><i class="fas fa-cog me-2 text-primary"></i>Settings</h1>
    </div>

    {render_settings_html(settings, chat_engine.get_available_models())}
    {BOTTOM_NAV_TEMPLATE}
    """

    return render_template_string(BASE_TEMPLATE,
                                title="Settings - RoleYU",
                                content=content,
                                user_profile=user_profile)

def render_recent_chats_html(recent_chats):
    if not recent_chats:
        return """
        <div class="empty-state">
            <i class="fas fa-comments fa-5x mb-3"></i>
            <h3 class="text-muted">No Recent Chats</h3>
            <p class="text-muted mb-4">Start chatting with characters to see them here!</p>
            <a href="/" class="btn btn-primary btn-lg">
                <i class="fas fa-home me-2"></i>Go to Homepage
            </a>
        </div>
        """

    html = '<div class="row">'
    for chat in recent_chats:
        html += f"""
        <div class="col-md-6 col-lg-4 mb-4">
            <div class="card character-card h-100">
                <div class="card-body">
                    <h5 class="card-title text-primary">{escape_html_builtin(chat['name'])}</h5>
                    <p class="text-muted small">
                        Last chat: {datetime.fromtimestamp(chat['last_chat']).strftime('%Y-%m-%d %H:%M')}
                    </p>
                    <a href="/chat/{chat['hash']}" class="btn btn-primary btn-sm">
                        <i class="fas fa-comments me-1"></i>Continue Chat
                    </a>
                </div>
            </div>
        </div>
        """
    html += '</div>'
    return html

def render_settings_html(settings, available_models):
    return f"""
    <div class="row justify-content-center">
        <div class="col-lg-8">
            <div class="card">
                <div class="card-body">
                    <form id="settingsForm">
                        <div class="mb-4">
                            <label class="form-label">
                                <i class="fas fa-robot me-1"></i>AI Model
                            </label>
                            <select class="form-select" name="ai_model" id="ai_model">
                                {get_model_options(available_models, settings.get('ai_model', 'Fluffball'))}
                            </select>
                        </div>

                        <div class="mb-4">
                            <label class="form-label">
                                <i class="fas fa-palette me-1"></i>Theme
                            </label>
                            <select class="form-select" name="theme" id="theme">
                                <option value="light" {'selected' if settings.get('theme') == 'light' else ''}>Light Mode</option>
                                <option value="dark" {'selected' if settings.get('theme') == 'dark' else ''}>Dark Mode</option>
                            </select>
                        </div>
                        <hr>

                        <div class="alert alert-danger">
                            <h6><i class="fas fa-exclamation-triangle me-1"></i>Danger Zone</h6>
                            <p class="mb-2">This action cannot be undone. All your characters and chat history will be permanently deleted.</p>
                            <button type="button" class="btn btn-danger" onclick="deleteAccount()">
                                <i class="fas fa-trash me-1"></i>Delete Account
                            </button>
                        </div>

                        <div class="text-center">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save me-1"></i>Save Settings
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script>
    document.getElementById('settingsForm').addEventListener('submit', function(e) {{
        e.preventDefault();
        saveSettings();
    }});

    document.getElementById('theme').addEventListener('change', function() {{
        applyTheme(this.value);
    }});

    applyTheme('{settings.get('theme', 'light')}');

    function saveSettings() {{
        const formData = new FormData(document.getElementById('settingsForm'));
        const settings = Object.fromEntries(formData);
        fetch('/api/settings', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(settings)
        }})
        .then(response => response.json())
        .then(data => {{
            if (data.status === 'success') {{
                alert('Settings saved successfully!');
            }}
        }})
        .catch(error => alert('Error saving settings'));
    }}

    function applyTheme(theme) {{
        document.documentElement.setAttribute('data-theme', theme);
    }}

    function deleteAccount() {{
        if (confirm('Are you sure you want to delete your account? This cannot be undone.')) {{
            if (confirm('This will delete ALL your characters and chat history. Are you absolutely sure?')) {{
                fetch('/api/delete-account', {{method: 'DELETE'}})
                .then(response => response.json())
                .then(data => {{
                    if (data.status === 'success') {{
                        alert(data.message);
                        window.location.href = '/';
                    }}
                }})
                .catch(error => alert('Error deleting account'));
            }}
        }}
    }}
    </script>
    """

def message_area():
    template = f"""
        <div class="chat-input-area">
            <div class="input-group">
                <textarea 
                    id="message-input" 
                    class="form-control" 
                    placeholder="Type your message..." 
                    rows="2" 
                    style="resize: none; border-radius: 20px 0 0 20px; overflow-y: hidden;" 
                    onkeydown="handleKeyPress(event)"></textarea>
                <button 
                    class="btn btn-primary" 
                    onclick="sendMessage()" 
                    style="border-radius: 0 20px 20px 0; padding: 0 20px;"
                    title="Send Message">
                    <i class="fas fa-paper-plane"></i>
                </button>
            </div>
            <div class="d-flex justify-content-between align-items-center mt-2">
                <small class="text-muted">
                    <i class="fas fa-info-circle me-1"></i>
                    <small class="text-muted">
                        All the characters' words are purely fictional and there are no elements of genuine suggestion or narrative!.
                    </small>
                </small>
                <div class="d-flex flex-column align-items-end gap-2">
                    <div class="d-flex align-items-center gap-2">
                        <small class="text-muted">Model:</small>
                        <select class="form-select form-select-sm" id="ai-model-select" style="width: auto;">
                            {get_model_options(ChatEngine().get_available_models(), get_user_settings().get('ai_model', 'Fluffball'))}
                        </select>
                    </div>
                    <button type="button" class="btn btn-sm w-auto bg-white border" onclick="saveAIModelSettings()">
                        <i class="fas fa-save me-1"></i>Save Settings
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>
    """
    return template

def get_model_options(available_models, current_model):
    options = ""
    for model_key, model_name in available_models.items():
        selected = 'selected' if model_key == current_model else ''
        options += f'<option value="{model_key}" {selected}>{model_name}</option>'
    return options

@app.route('/api/random-characters')
def api_random_characters():
    page = int(request.args.get('page', 0))
    limit = int(request.args.get('limit', 36))

    characters = get_random_characters(limit * (page + 1))
    start_index = limit * page

    return jsonify({
        "status": "success",
        "characters": characters[start_index:start_index + limit],
        "has_more": len(characters) > start_index + limit
    })

@app.route('/api/available-models')
def api_available_models():
    chat_engine = ChatEngine()
    return jsonify({
        "status": "success",
        "models": chat_engine.get_available_models()
    })

@app.route('/api/recent-chats/add', methods=['POST'])
def api_add_recent_chat():
    try:
        data = request.get_json()
        user_id = get_user_id()
        char_hash = data.get('character_hash')
        char_name = data.get('character_name')
        add_to_recent_chats(user_id, char_hash, char_name)

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    user_id = get_user_id()
    user_profile = get_user_profile()
    api_error = None
    characters = {}

    try:
        characters = CharacterAPI.get_characters()
        cleanup_expired_cache()
    except Exception as e:
        api_error = f"Failed to fetch characters: {str(e)}"
        print(f"API Error: Undf")

    total_chars = 0
    total_names = 0

    try:
        if characters:
            total_chars = sum(len(char_list) if isinstance(char_list, list) else 1 for char_list in characters.values())
            total_names = len(characters)
    except Exception as e:
        print(f"Stats calculation error: Undf")
        total_chars = 0
        total_names = 0

    content = render_template_string(INDEX_TEMPLATE, 
                                   characters=characters, 
                                   base_url=BASE_URL,
                                   total_chars=total_chars,
                                   total_names=total_names,
                                   api_error=api_error)

    return render_template_string(BASE_TEMPLATE,
                                title="RoleYU - Dashboard", 
                                content=content,
                                user_profile=user_profile)

def save_user_avatar_permanent(avatar_file):
    try:
        user_id = get_user_id()
        permanent_data = get_user_permanent_data()

        avatar_content = avatar_file.read()
        compressed_avatar = compress_image(avatar_content, quality=50, max_width=500, max_height=500)
        permanent_token = f"perm_avatar_{user_id}_{int(time.time())}"

        IMAGE_CACHE[permanent_token] = {
            'data': compressed_avatar,
            'content_type': avatar_file.content_type or 'image/jpeg',
            'expires': time.time() + (365 * 24 * 3600)  # 1 year
        }

        avatar_meta = {
            'token': permanent_token,
            'content_type': avatar_file.content_type or 'image/jpeg',
            'timestamp': time.time(),
            'size': len(avatar_content)
        }

        permanent_data['avatar'] = avatar_meta
        save_user_permanent_data(permanent_data)

        return permanent_token
    except Exception as e:
        print(f"Error saving permanent avatar: Undf")
        return None

@app.route('/profile', methods=['GET', 'POST'])
def user_profile():
    user_profile = get_user_profile()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        personalities = request.form.get('personalities', '').strip()
        avatar = request.files.get('avatar')

        if not name:
            flash('Name must be filled!', 'error')
            return redirect(url_for('user_profile'))

        if not personalities:
            flash('Personality must be filled!', 'error')
            return redirect(url_for('user_profile'))

        if avatar and avatar.filename != '':
            if not allowed_file(avatar.filename):
                flash('File format not allowed!', 'error')
                return redirect(url_for('user_profile'))

            avatar.seek(0, 2)
            if avatar.tell() > MAX_FILE_SIZE:
                flash('File size too large!', 'error')
                return redirect(url_for('user_profile'))
            avatar.seek(0)

            avatar_token = save_user_avatar_permanent(avatar)
            if avatar_token:
                user_profile['avatar_token'] = avatar_token

        save_user_profile(name, personalities, avatar_token) if avatar and avatar.filename != '' else save_user_profile(name, personalities)
        flash('✨ Profile saved successfully!', 'success')

        response = redirect(url_for('user_profile'))
        response.set_cookie(f'user_data_{get_user_id()}', 
                          json.dumps(get_user_permanent_data()),
                          max_age=365*24*3600)
        return response

    content = render_template_string(PROFILE_TEMPLATE, user_profile=user_profile)
    return render_template_string(BASE_TEMPLATE, 
                                title="User Profile Settings - RoleYU", 
                                content=content,
                                user_profile=user_profile,
                                navbar_content=render_navbar(user_profile),
                                flash_messages=render_flash_messages(),
                                bottom_nav=BOTTOM_NAV_TEMPLATE,
                                custom_scripts="")

@app.route('/my-characters')
def my_characters():
    user_id = get_user_id()
    user_profile = get_user_profile()

    try:
        characters = CharacterAPI.get_characters()
        my_chars = []

        for char_name, char_versions in characters.items():
            for char_data in char_versions:
                if isinstance(char_data, dict) and char_data.get('creator_id') == user_id:
                    my_chars.append((char_name, char_data))

    except Exception as e:
        print(f"Error loading my characters: Undf")
        my_chars = []

    content = render_template_string(MY_CHARACTERS_TEMPLATE, my_characters=my_chars)
    return render_template_string(BASE_TEMPLATE, 
                                title="My Character - RoleYU", 
                                content=content,
                                bottom_nav=BOTTOM_NAV_TEMPLATE,
                                user_profile=user_profile)

@app.route('/add', methods=['GET', 'POST'])
def add_characters():
    user_id = get_user_id()
    user_profile = get_user_profile()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        personalities = request.form.get('personalities', '').strip()
        style = request.form.get('style', '').strip()
        description = request.form.get('description', '').strip()
        greeting = request.form.get('greeting', '').strip()
        photo = request.files.get('photo')

        if not name:
            flash('Character name must be filled!', 'error')
            return redirect(url_for('add_character'))

        if not personalities:
            flash('Personality must be filled!', 'error')
            return redirect(url_for('add_character'))

        if not greeting:
            greeting = DEFAULT_GREETING

        if photo and photo.filename != '':
            if not allowed_file(photo.filename):
                flash('File format not allowed!', 'error')
                return redirect(url_for('add_character'))

            photo.seek(0, 2)
            if photo.tell() > MAX_FILE_SIZE:
                flash('File size too large, max 2MB!', 'error')
                return redirect(url_for('add_character'))
            photo.seek(0)

        result = CharacterAPI.add_character(name, personalities, style, description, greeting, photo, user_id)

        if result.get('status') == 'success':
            flash(f'✨ Character "{escape_html_builtin(name)}" created successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'❌ Failed to create character: {result.get("message", "Unknown error")}', 'error')

    content = render_template_string(ADD_TEMPLATE)
    return render_template_string(BASE_TEMPLATE, 
                                title="Create New Character - RoleYU", 
                                content=content,
                                user_profile=user_profile,
                                navbar_content=render_navbar(user_profile),
                                flash_messages=render_flash_messages(),
                                bottom_nav=BOTTOM_NAV_TEMPLATE,
                                custom_scripts="")

@app.route('/remove/<hash_id>')
def remove_character(hash_id):
    user_id = get_user_id()
    result = CharacterAPI.remove_character(hash_id, user_id)

    if result.get('status') == 'success':
        flash('🗑️ Character successfully deleted!', 'success')
    else:
        flash(f'❌ Failed: {result.get("message", "Unknown error")}', 'error')

    return redirect(url_for('index'))

@app.route('/chat/<char_hash>')
def chat_with_character(char_hash):
    user_id = get_user_id()
    user_profile = get_user_profile()

    try:
        char_name, char_data = CharacterAPI.get_character_by_hash(char_hash)
        if not char_data:
            flash('Character not found!', 'error')
            return redirect(url_for('index'))

        add_to_recent_chats(user_id, char_hash, char_name)
        greeting = format_greeting(char_data['greetings'], user_profile["name"], char_name)

        char_data['greetings'] = greeting
        CHAT_TEMPLATE = f"""
{CHAT_STYLE}
{CHAT_BODY}
{message_area()}
{CHAT_FUNC}
"""

        content = render_template_string(CHAT_TEMPLATE,
                                       character_name=char_name,
                                       character=char_data,
                                       character_hash=char_hash,
                                       user_profile=user_profile)

        return render_template_string(BASE_TEMPLATE,
                                    title=f"Chat with {char_name} - RoleYU",
                                    content=content,
                                    user_profile=user_profile,
                                    navbar_content=render_navbar(user_profile),
                                    flash_messages=render_flash_messages(),
                                    bottom_nav=BOTTOM_NAV_TEMPLATE,
                                    custom_scripts="")

    except Exception as e:
        flash(f'Error loading character: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/temp_image/<token>')
def serve_temp_image(token):
    try:
        cache_entry = get_cached_image(token)
        if cache_entry:
            return send_file(
                io.BytesIO(cache_entry['data']),
                mimetype=cache_entry['content_type'],
                as_attachment=False
            )
        else:
            return '', 404
    except Exception as e:
        print(f"Error serving temp image: Undf")
        return '', 404

def stream_ai_response(conversation_history, model=None):
    chat_engine = ChatEngine()
    if model is None:
        user_settings = get_user_settings()
        model = user_settings.get('ai_model', 'Fluffball')

    try:
        response = chat_engine.send_to_ai(conversation_history, model)
        if not response:
            yield "data: " + json.dumps({"error": "Failed to get response"}) + "\n\n"
            return

        accumulated_text = ""
        for line in response.iter_lines(decode_unicode=True):
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get("type") == "content":
                        content = data["content"]
                        if 'Sponsor' not in content and '**Sponsor**' not in content:
                            accumulated_text += content
                            yield "data: " + json.dumps({
                                "type": "content", 
                                "content": content,
                                "accumulated": accumulated_text
                            }) + "\n\n"
                except json.JSONDecodeError:
                    continue

        yield "data: " + json.dumps({"type": "done", "final_content": accumulated_text}) + "\n\n"

    except Exception as e:
        print(f"Stream error: Undf")
        yield "data: " + json.dumps({"error": str(e)}) + "\n\n"

@app.route('/api/chat-stream', methods=['POST'])
def api_chat_stream():
    try:
        data = request.get_json()
        conversation_history = data.get('conversation_history', [])
        model = data.get('model', 'Fluffball')

        return Response(
            stream_ai_response(conversation_history, model),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'X-Accel-Buffering': 'no'
            }
        )
    except Exception as e:
        print(f"Chat stream error: Undf")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def api_chat():
    try:
        data = request.get_json()
        char_hash = data.get('character_hash')
        session_id = data.get('session_id', 'default')
        message = data.get('message')
        conversation_history = data.get('conversation_history', [])

        if not char_hash or not message:
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        char_name, char_data = CharacterAPI.get_character_by_hash(char_hash)
        if not char_data:
            return jsonify({"status": "error", "message": "Character not found"}), 404

        chat_engine = ChatEngine()
        ai_response = chat_engine.get_valid_response(conversation_history)

        return jsonify({
            "status": "success",
            "response": ai_response,
            "character_name": char_name
        })

    except Exception as e:
        print(f"Chat API error: Undf")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/save-session', methods=['POST'])
def api_save_session():
    try:
        data = request.get_json()
        #print(data['conversation_history'][1]['content'])
        user_id = get_user_id()
        char_hash = data.get('character_hash')
        session_id = data.get('session_id')
        conversation_history = data.get('conversation_history', [])
        char_name = data.get('character_name', '')
        #charsname=char_name;templates=data['conversation_history'][1]['content']

        save_chat_session(user_id, f"{char_hash}_{session_id}", conversation_history, char_name)

        return jsonify({"status": "success"})
    except Exception as e:
        print(f"Save session error: Undf")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/chat-sessions/<char_hash>')
def api_get_chat_sessions(char_hash):
    global charsname, templates
    try:
        user_id = get_user_id()
        user_sessions = get_chat_sessions(user_id)

        char_sessions = {k.split('_', 1)[1]: v for k, v in user_sessions.items() if k.startswith(char_hash + '_')}

        return jsonify({
            "status": "success",
            "sessions": char_sessions
        })
    except Exception as e:
        print(f"Get sessions error: Undf")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/chat-session/<char_hash>/<session_id>')
def api_get_chat_session(char_hash, session_id):
    try:
        user_id = get_user_id()
        user_sessions = get_chat_sessions(user_id)

        full_session_id = f"{char_hash}_{session_id}"
        session_data = user_sessions.get(full_session_id)

        if session_data:
            return jsonify({
                "status": "success",
                "history": session_data['history']
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Session not found"
            })
    except Exception as e:
        print(f"Get session error: Undf")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/settings', methods=['GET', 'POST'])
def api_user_settings():
    user_id = get_user_id()
    if request.method == 'POST':
        data = request.get_json()
        settings = get_user_settings()

        if 'theme' in data:
            settings['theme'] = data['theme']
        if 'ai_model' in data:
            settings['ai_model'] = data['ai_model']
        if 'language' in data:
            settings['language'] = data['language']

        save_user_settings(settings)

        response = jsonify({"status": "success", "settings": settings})
        response.set_cookie(f'user_data_{user_id}', 
                          json.dumps(get_user_permanent_data()),
                          max_age=365*24*3600)  # 1 year
        return response

    return jsonify({"status": "success", "settings": get_user_settings()})

@app.route('/api/recent-chats')
def api_recent_chats():
    user_id = get_user_id()
    recent_chats = get_recent_chats(user_id)
    return jsonify({"status": "success", "recent_chats": recent_chats})

@app.route('/api/search-characters')
def api_search_characters():
    query = request.args.get('q', '')
    if not query:
        return jsonify({"status": "error", "message": "Query parameter required"})

    results = search_characters(query)
    return jsonify({"status": "success", "characters": results})

@app.route('/api/chat-sessions/<char_hash>/rename', methods=['POST'])
def api_rename_chat_session(char_hash):
    try:
        data = request.get_json()
        user_id = get_user_id()
        session_id = data.get('session_id')
        new_name = data.get('new_name', '').strip()

        if not new_name:
            return jsonify({"status": "error", "message": "Name is required"}), 400

        if rename_chat_session(user_id, session_id, new_name):
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "Session not found"}), 404

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/chat-sessions/<session_id>/delete', methods=['DELETE'])
def api_delete_chat_session(session_id):
    try:
        user_id = get_user_id()
        if delete_permanent_chat_session(user_id, session_id):
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "Session not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/delete-account', methods=['DELETE'])
def api_delete_account():
    try:
        user_id = get_user_id()
        characters = CharacterAPI.get_characters()
        deleted_count = 0

        for char_name, char_versions in characters.items():
            for char_data in char_versions:
                if isinstance(char_data, dict) and char_data.get('creator_id') == user_id:
                    CharacterAPI.remove_character(char_data.get('hash'), user_id)
                    deleted_count += 1

        session.clear()
        if user_id in PERMANENT_USER_CACHE:
            del PERMANENT_USER_CACHE[user_id]
        if user_id in RECENT_CHATS_CACHE:
            del RECENT_CHATS_CACHE[user_id]
        if user_id in CHAT_SESSIONS:
            del CHAT_SESSIONS[user_id]

        response = jsonify({
            "status": "success", 
            "message": f"Account deleted successfully. {deleted_count} characters removed."
        })

        response.set_cookie(f'user_data_{user_id}', '', expires=0)
        return response
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/delete-message', methods=['POST'])
def api_delete_message():
    try:
        data = request.get_json()
        user_id = get_user_id()
        char_hash = data.get('character_hash')
        session_id = data.get('session_id')
        message_index = data.get('message_index')+1

        full_session_id = f"{char_hash}_{session_id}"

        if delete_message_from_history(user_id, full_session_id, message_index):
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "Failed to delete message"}), 400

    except Exception as e:
        print(f"Delete message error: Undf")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/edit-message', methods=['POST'])
def api_edit_message():
    try:
        data = request.get_json()
        user_id = get_user_id()
        char_hash = data.get('character_hash')
        session_id = data.get('session_id')
        message_index = data.get('message_index')+1
        new_content = data.get('new_content')
        full_session_id = f"{char_hash}_{session_id}"

        if CHAT_SESSIONS[user_id][full_session_id]['history'][message_index]['role'] == 'user':
            user_profile = get_user_profile()
            formatted_content = f"[USER_NAME]: {user_profile['name']} [USER_PERSONALITIES]: {user_profile['personalities']} [USER_MESSAGE]: {new_content}"
        else:
            formatted_content = new_content

        if edit_message_in_history(user_id, full_session_id, message_index, formatted_content):
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "Failed to edit message"}), 400

    except Exception as e:
        print(f"Edit message error: Undf")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/health')
def health_check():
    try:
        response = requests.get(f"{BASE_URL}/character.json", timeout=5)
        backend_status = "healthy" if response.status_code == 200 else "unhealthy"

        chat_response = requests.get(CHAT_API_URL.replace('/backend-api/v2/conversation', '/'), timeout=5)
        chat_status = "healthy" if chat_response.status_code == 200 else "unhealthy"
    except:
        backend_status = "unreachable"
        chat_status = "unreachable"

    return jsonify({
        "status": "healthy",
        "version": "4.0.0",
        "features": {
            "streaming_responses": True,
            "permanent_storage": True,
            "session_management": True,
            "multi_language": True,
            "dark_mode": True
        },
        "backend_status": backend_status,
        "chat_api_status": chat_status,
        "cached_images": len(IMAGE_CACHE),
        "active_sessions": len(CHAT_SESSIONS),
        "permanent_users": len(PERMANENT_USER_CACHE),
        "recent_chats": sum(len(chats) for chats in RECENT_CHATS_CACHE.values())
    })

@app.errorhandler(404)
def not_found_error(error):
    user_profile = get_user_profile()
    content = """
    <div class="text-center py-5">
        <i class="fas fa-robot fa-5x text-muted mb-4"></i>
        <h1 class="display-4 text-muted">404</h1>
        <h3>Page Not Found</h3>
        <p class="text-muted mb-4">The page you're looking for doesn't exist or has been moved.</p>
        <div class="d-flex gap-2 justify-content-center">
            <a href="/" class="btn btn-primary">
                <i class="fas fa-home me-1"></i>Go Home
            </a>
            <button onclick="history.back()" class="btn btn-outline-secondary">
                <i class="fas fa-arrow-left me-1"></i>Go Back
            </button>
        </div>
    </div>
    """ + BOTTOM_NAV_TEMPLATE
    
    return render_template_string(BASE_TEMPLATE,
                                title="Page Not Found - RoleYU",
                                content=content,
                                user_profile=user_profile,
                                navbar_content=render_navbar(user_profile),
                                flash_messages="",
                                bottom_nav=BOTTOM_NAV_TEMPLATE,
                                custom_scripts=""), 404

@app.errorhandler(500)
def internal_error(error):
    user_profile = get_user_profile()
    content = """
    <div class="text-center py-5">
        <i class="fas fa-exclamation-triangle fa-5x text-warning mb-4"></i>
        <h1 class="display-4 text-muted">500</h1>
        <h3>Internal Server Error</h3>
        <p class="text-muted mb-4">Something went wrong on our end. Please try again later.</p>
        <div class="d-flex gap-2 justify-content-center">
            <a href="/" class="btn btn-primary">
                <i class="fas fa-home me-1"></i>Go Home
            </a>
            <button onclick="location.reload()" class="btn btn-outline-warning">
                <i class="fas fa-refresh me-1"></i>Retry
            </button>
        </div>
    </div>
    """ + BOTTOM_NAV_TEMPLATE

    return render_template_string(BASE_TEMPLATE,
                                title="Server Error - RoleYU",
                                content=content,
                                user_profile=user_profile,
                                navbar_content=render_navbar(user_profile),
                                flash_messages="",
                                bottom_nav=BOTTOM_NAV_TEMPLATE,
                                custom_scripts=""), 500


@app.route('/api/character-stats')
def api_character_stats():
    try:
        characters = CharacterAPI.get_characters()
        user_id = get_user_id()

        total_characters = 0
        user_characters = 0
        popular_characters = []

        for char_name, char_versions in characters.items():
            if isinstance(char_versions, list):
                for char_data in char_versions:
                    total_characters += 1
                    if isinstance(char_data, dict):
                        if char_data.get('creator_id') == user_id:
                            user_characters += 1

                        popular_characters.append({
                            'name': char_name,
                            'hash': char_data.get('hash'),
                            'chats': random.randint(1, 100)
                        })
            else:
                total_characters += 1

        popular_characters.sort(key=lambda x: x.get('chats', 0), reverse=True)
        popular_characters = popular_characters[:10]

        return jsonify({
            "status": "success",
            "stats": {
                "total_characters": total_characters,
                "user_characters": user_characters,
                "popular_characters": popular_characters,
                "recent_chats_count": len(get_recent_chats(user_id))
            }
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/export-user-data')
def api_export_user_data():
    try:
        user_id = get_user_id()

        export_data = {
            "user_id": user_id,
            "export_timestamp": datetime.now().isoformat(),
            "profile": get_user_profile(),
            "settings": get_user_settings(),
            "permanent_data": get_user_permanent_data(),
            "recent_chats": get_recent_chats(user_id),
            "chat_sessions": get_chat_sessions(user_id),
            "created_characters": []
        }

        characters = CharacterAPI.get_characters()
        for char_name, char_versions in characters.items():
            for char_data in char_versions:
                if isinstance(char_data, dict) and char_data.get('creator_id') == user_id:
                    export_data["created_characters"].append({
                        "name": char_name,
                        "data": char_data
                    })

        response = Response(
            json.dumps(export_data, indent=2),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=kgpt_user_data_{user_id}_{int(time.time())}.json'
            }
        )

        return response

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/import-user-data', methods=['POST'])
def api_import_user_data():
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file provided"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "error", "message": "No file selected"}), 400

        if not file.filename.endswith('.json'):
            return jsonify({"status": "error", "message": "Only JSON files are allowed"}), 400

        try:
            import_data = json.loads(file.read())
        except json.JSONDecodeError:
            return jsonify({"status": "error", "message": "Invalid JSON file"}), 400

        user_id = get_user_id()

        if 'profile' in import_data:
            profile_data = import_data['profile']
            save_user_profile(
                profile_data.get('name', f'User_{user_id[:8]}'),
                profile_data.get('personalities', 'Imported user profile')
            )

        if 'settings' in import_data:
            save_user_settings(import_data['settings'])

        import_sessions = request.form.get('import_sessions') == 'true'
        if import_sessions and 'chat_sessions' in import_data:
            for session_id, session_data in import_data['chat_sessions'].items():
                save_permanent_chat_session(user_id, session_id, session_data)

        return jsonify({
            "status": "success",
            "message": "Data imported successfully",
            "imported": {
                "profile": 'profile' in import_data,
                "settings": 'settings' in import_data,
                "sessions": import_sessions and 'chat_sessions' in import_data
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/cookie-stats')
def api_cookie_stats():
    try:
        user_id = get_user_id()
        if user_id in PERMANENT_USER_CACHE:
            full_data = PERMANENT_USER_CACHE[user_id]
            optimized_data = optimize_user_data_for_cookie(full_data)

            full_size = len(json.dumps(full_data))
            optimized_size = len(json.dumps(optimized_data))
            compressed_size = len(compress_data(optimized_data)) if compress_data(optimized_data) else 0

            return jsonify({
                "status": "success",
                "stats": {
                    "user_id": user_id,
                    "full_data_size": full_size,
                    "optimized_size": optimized_size,
                    "compressed_size": compressed_size,
                    "compression_ratio": f"{(compressed_size/full_size*100):.1f}%" if full_size > 0 else "0%",
                    "cookie_limit": COOKIE_MAX_SIZE,
                    "within_limit": compressed_size <= COOKIE_MAX_SIZE
                }
            })
        else:
            return jsonify({
                "status": "success",
                "stats": {"message": "No user data found"}
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def start_background_tasks():
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()

if __name__ == '__main__':
    print("[+] RP Deployed at: http://127.0.0.1:5000")

    import threading
    def periodic_cleanup():
        while True:
            time.sleep(300)
            cleanup_expired_cache()

    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()

    app.run(
        host='0.0.0.0',
        port=5000,
        threaded=True
    )


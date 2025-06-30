# -*- coding: utf-8 -*-
import re

def redact(messages):
    for message in messages:
        message['content'] = redact_content(message['content'])
    return messages

def redact_content(content):
    r = content
    # --- Original repo logic (one param at a time) ---
    r = redact_cli_parameter('api-key', r)
    r = redact_cli_parameter('key', r)
    r = redact_cli_parameter('password', r)
    r = redact_cli_parameter('passphrase', r)
    r = redact_cli_parameter('secret', r)
    r = redact_pem_encoded_private_key(r)
    r = redact_pem_encoded_private_key_block(r)
    # --- Additional new patterns (additive, deduped) ---
    r = redact_additional_patterns(r)
    return r

def redact_cli_parameter(param, content):
    pattern = r'--{param}([= ])(["\']?)\S+\2'.format(param=param)
    replace_with = r'--{param}\1\2<REDACTED>\2'.format(param=param)
    return re.sub(pattern, replace_with, content)

def redact_pem_encoded_private_key(content):
    pattern = (r'-----BEGIN ([A-Z0-9]+) PRIVATE KEY-----\n'
               r'[\s\S]+?\n'
               r'-----END \1 PRIVATE KEY-----')
    replace_with = (r'-----BEGIN \1 PRIVATE KEY-----\n'
                    r'<REDACTED>\n'
                    r'-----END \1 PRIVATE KEY-----')
    return re.sub(pattern, replace_with, content, flags=re.DOTALL)

def redact_pem_encoded_private_key_block(content):
    pattern = (r'-----BEGIN ([A-Z0-9]+) PRIVATE KEY BLOCK-----\n'
               r'[\s\S]+?\n'
               r'-----END \1 PRIVATE KEY BLOCK-----')
    replace_with = (r'-----BEGIN \1 PRIVATE KEY BLOCK-----\n'
                    r'<REDACTED>\n'
                    r'-----END \1 PRIVATE KEY BLOCK-----')
    return re.sub(pattern, replace_with, content, flags=re.DOTALL)

def redact_additional_patterns(content):
    patterns = [
        # MAC address
        (r'\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b', '<REDACTED_MAC>'),
        # UUID/Boot ID
        (r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', '<REDACTED_UUID>'),
        # PCI/USB ID (device path style)
        (r'\b[0-9a-fA-F]{4}:[0-9a-fA-F]{4}\b', '<REDACTED_PCIID>'),
        # IPv4 address
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<REDACTED_IPV4>'),
        # IPv6 address
        (r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', '<REDACTED_IPV6>'),
        # Hostname (simple)
        (r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', '<REDACTED_HOSTNAME>'),
        # Email address
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '<REDACTED_EMAIL>'),
        # Boot/Kernel/Session IDs (long hex strings)
        (r'\b[0-9a-fA-F]{32,}\b', '<REDACTED_HEXID>')
    ]
    for pattern, repl in patterns:
        content = re.sub(pattern, repl, content, flags=re.MULTILINE)
    return content

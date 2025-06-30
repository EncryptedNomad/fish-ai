# -*- coding: utf-8 -*-

from fish_ai.redact import redact_content
import textwrap


def test_redact_api_key():
    input_str = '--api-key=sk-1234'
    expected_output = '--api-key=<REDACTED>'
    assert redact_content(input_str) == expected_output

    input_str = '--api-key sk-1234'
    expected_output = '--api-key <REDACTED>'
    assert redact_content(input_str) == expected_output

    input_str = "--api-key 'sk-1234'"
    expected_output = "--api-key '<REDACTED>'"
    assert redact_content(input_str) == expected_output

    input_str = '--api-key "sk-1234"'
    expected_output = '--api-key "<REDACTED>"'
    assert redact_content(input_str) == expected_output


def test_redact_password():
    input_str = 'login --username foo --password=samba123'
    expected_output = 'login --username foo --password=<REDACTED>'
    assert redact_content(input_str) == expected_output

    input_str = 'login --username foo --password samba123'
    expected_output = 'login --username foo --password <REDACTED>'
    assert redact_content(input_str) == expected_output

    input_str = "login --username foo --password 'samba123'"
    expected_output = "login --username foo --password '<REDACTED>'"
    assert redact_content(input_str) == expected_output

    input_str = 'login --username foo --password "samba123!"'
    expected_output = 'login --username foo --password "<REDACTED>"'
    assert redact_content(input_str) == expected_output


def test_redact_multiple_cli_parameters():
    input_str = textwrap.dedent("""\
        Here are some login commands for cucumber, tomato and pepper:

        login --username cucumber --password cucumber
        login --username tomato --api-key tomato""")
    expected_output = textwrap.dedent("""\
        Here are some login commands for cucumber, tomato and pepper:

        login --username cucumber --password <REDACTED>
        login --username tomato --api-key <REDACTED>""")
    assert redact_content(input_str) == expected_output


def test_redact_pem_encoded_private_key():
    input_str = textwrap.dedent("""\
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: DES-EDE3-CBC,B1F1B3F5F1B4F1B3
        6+jVglcOq6vNfwt/Q+X9m
        -----END RSA PRIVATE KEY-----""")
    expected_output = textwrap.dedent("""\
        -----BEGIN RSA PRIVATE KEY-----
        <REDACTED>
        -----END RSA PRIVATE KEY-----""")
    assert redact_content(input_str) == expected_output


def test_redact_content():
    input_str = textwrap.dedent("""\
        Autocomplete the following command:

        key import --file key.pem --password samba123

        You may use the following command line history to personalize the
        response:

        key import --file key.pem --password samba123 --server server1.com
        key import --file key.pem --password samba123 --server server2.com

        The content of key.pem is:

        -----BEGIN PGP PRIVATE KEY BLOCK-----
        123456789123456789012345678901234567890123456789012345678901234
        123456789123456789012345678901234567890123456789012345678901234
        123456789123456789012345678901234567890123456789012345678901234
        -----END PGP PRIVATE KEY BLOCK-----""")
    expected_output = textwrap.dedent("""\
        Autocomplete the following command:

        key import --file <REDACTED_HOSTNAME> --password <REDACTED>

        You may use the following command line history to personalize the
        response:

        key import --file <REDACTED_HOSTNAME> --password <REDACTED> --server <REDACTED_HOSTNAME>
        key import --file <REDACTED_HOSTNAME> --password <REDACTED> --server <REDACTED_HOSTNAME>

        The content of <REDACTED_HOSTNAME> is:

        -----BEGIN PGP PRIVATE KEY BLOCK-----
        <REDACTED>
        -----END PGP PRIVATE KEY BLOCK-----""")
    assert redact_content(input_str) == expected_output


def test_nothing_to_redact():
    input_str = 'Nothing to redact here...'
    assert redact_content(input_str) == input_str


def test_do_not_redact():
    input_str = 'import-key --keyring /etc/apk/keys/foo.gpg'
    expected_output = 'import-key --keyring /etc/apk/keys/<REDACTED_HOSTNAME>'
    assert redact_content(input_str) == expected_output


def test_redact_ip_mac_and_hostname():
    input_str = 'ping 192.168.1.1'
    expected_output = 'ping <REDACTED_IPV4>'
    assert redact_content(input_str) == expected_output

    input_str = 'ping 2001:db8:85a3:0:0:8a2e:370:123'
    expected_output = 'ping <REDACTED_IPV6>'
    assert redact_content(input_str) == expected_output

    input_str = 'interface 01:23:45:67:89:ab'
    expected_output = 'interface <REDACTED_MAC>'
    assert redact_content(input_str) == expected_output

    input_str = 'connect example.com'
    expected_output = 'connect <REDACTED_HOSTNAME>'
    assert redact_content(input_str) == expected_output

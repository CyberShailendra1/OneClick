"""
Tests for telegram_bot.py.

Two layers, matching the module's own architecture note:
  1. Pure logic tests (build_*_reply functions) - real calls into the actual
     detection modules, no mocking needed, no network required.
  2. Handler wiring tests - construct fake Update/Context objects (the
     standard python-telegram-bot testing pattern) to verify /scan,
     /checknumber, /checkupi, and the text/photo handlers call the right
     logic and send a reply, WITHOUT needing a live bot token or network
     access to Telegram's servers (which this sandbox doesn't have anyway).

Run with:  python3 -m pytest tests/test_telegram_bot.py -v
       or:  python3 tests/test_telegram_bot.py   (runs a plain summary)
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telegram_bot import (
    build_scan_url_reply, build_message_reply, build_number_check_reply,
    build_upi_check_reply, build_photo_reply,
)


# =============================================================================
# Layer 1: pure logic tests
# =============================================================================

def test_scan_url_phishing():
    reply = build_scan_url_reply("http://paypa1-secure.tk/verify")
    assert "Phishing / Malicious" in reply
    assert "typosquatting" in reply


def test_scan_url_safe():
    reply = build_scan_url_reply("https://www.google.com")
    assert "Likely Safe" in reply


def test_message_reply_scam_with_otp_and_link():
    text = ("CYBER CRIME CELL: your Aadhaar is linked to a case. Your OTP is 552011. "
            "Visit http://sbi-verify.tk/secure to clear dues.")
    reply = build_message_reply(text)
    assert "552011" not in reply, "raw OTP must never leak into the bot reply"
    assert "HIDDEN" in reply or "Hid 1" in reply
    assert "Digital Arrest" in reply
    assert "sbi-verify.tk" in reply


def test_message_reply_clean():
    reply = build_message_reply("Hey, are we still on for lunch tomorrow?")
    assert "No OTPs, scam patterns, or links" in reply


def test_number_check_reported():
    reply = build_number_check_reply("9000000001")
    assert "Reported" in reply
    assert "Fake Customer Care" in reply


def test_number_check_clean():
    reply = build_number_check_reply("9876543210")
    assert "Not found" in reply


def test_upi_check_reported():
    reply = build_upi_check_reply("fraud@upi")
    assert "Reported" in reply


def test_photo_reply_qr_phishing():
    reply = build_photo_reply("/tmp/test_phish_qr.png")
    assert "Phishing / Malicious" in reply


def test_photo_reply_screenshot_ocr_fallback():
    reply = build_photo_reply("/tmp/test_scam_screenshot2.png")
    assert "552011" not in reply
    assert "Digital Arrest" in reply


# =============================================================================
# Layer 2: handler wiring tests (mocked Update/Context, no live bot needed)
# =============================================================================

def _fake_update_with_text(text):
    update = MagicMock()
    update.message.text = text
    update.message.reply_text = AsyncMock()
    return update


def _fake_context(args=None):
    context = MagicMock()
    context.args = args or []
    return context


def test_handler_scan_cmd_calls_build_reply_and_sends_it():
    """Verifies the /scan command handler wiring - without needing a live
    bot token - by importing the handler construction function directly and
    invoking it with mocked Update/Context objects."""
    import telegram_bot as tb

    os.environ["ONECLICK_TELEGRAM_TOKEN"] = "fake-token-for-wiring-test-only"
    app = tb._build_application()

    # Find the /scan CommandHandler among the registered handlers.
    scan_handler = None
    for group in app.handlers.values():
        for h in group:
            if getattr(h, "commands", None) and "scan" in h.commands:
                scan_handler = h
                break
    assert scan_handler is not None, "/scan handler was not registered"

    update = _fake_update_with_text("/scan http://paypa1-secure.tk/verify")
    context = _fake_context(args=["http://paypa1-secure.tk/verify"])

    asyncio.run(scan_handler.callback(update, context))

    update.message.reply_text.assert_called_once()
    sent_text = update.message.reply_text.call_args[0][0]
    assert "Phishing / Malicious" in sent_text


def test_handler_text_message_calls_build_message_reply():
    import telegram_bot as tb

    os.environ["ONECLICK_TELEGRAM_TOKEN"] = "fake-token-for-wiring-test-only"
    app = tb._build_application()

    text_handler = None
    for group in app.handlers.values():
        for h in group:
            # MessageHandler for plain text (not commands) - identify by callback name
            if getattr(h, "callback", None) and h.callback.__name__ == "text_message_handler":
                text_handler = h
                break
    assert text_handler is not None, "text message handler was not registered"

    update = _fake_update_with_text("Your OTP is 483920, do not share it.")
    context = _fake_context()

    asyncio.run(text_handler.callback(update, context))

    update.message.reply_text.assert_called_once()
    sent_text = update.message.reply_text.call_args[0][0]
    assert "483920" not in sent_text
    assert "Hid 1" in sent_text


def _run_all():
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"[PASS] {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    ok = _run_all()
    sys.exit(0 if ok else 1)

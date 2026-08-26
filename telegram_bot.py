"""
OneClick Telegram Bot.

Lets people forward a suspicious link, message, screenshot, or QR code
directly to a Telegram bot and get an instant flag-only verdict - no need to
open the web dashboard. Reuses the exact same detection modules as the
Streamlit app and REST API, so results are identical across every interface.

DESIGN PRINCIPLE (same as the rest of OneClick): flag-only. The bot only
ever replies with information - it never blocks contacts, deletes messages,
or takes any action on the user's behalf.

ARCHITECTURE NOTE FOR TESTABILITY: all the actual "thinking" happens in the
build_*_reply() functions below, which are plain functions (str in, str out)
with zero Telegram-specific code. This means they can be - and are, see
tests/test_telegram_bot.py - fully unit tested without needing a live bot
token or network access to Telegram's servers. The telegram.ext handlers at
the bottom are thin wrappers that just call these functions and send the
result back.

SETUP:
    1. Message @BotFather on Telegram, run /newbot, get a token.
    2. export ONECLICK_TELEGRAM_TOKEN="your-token-here"
    3. (optional) export ONECLICK_VT_API_KEY="your-virustotal-key"
    4. python3 telegram_bot.py

TESTING STATUS: the reply-building logic (build_scan_url_reply,
build_message_reply, etc.) is fully unit tested with real calls into the
same modules the web app uses. The actual python-telegram-bot polling loop
against Telegram's live servers could NOT be tested end-to-end in this
environment (no network path to api.telegram.org from this sandbox) - the
handler wiring was instead verified with mocked Update/Context objects
(see tests/test_telegram_bot.py), which confirms the handlers call the
right functions and reply with the right text, without needing a live bot.
"""

import logging
import os
import tempfile

from modules.phishing_scanner import scan_url, extract_urls_from_text
from modules.otp_guard import redact_message
from modules.scam_pattern_detector import detect_scam_patterns
from modules.scam_lookup import check_phone_number, check_upi_id
from modules import database

try:
    from modules.qr_scanner import scan_qr_image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

try:
    from modules.ocr_scanner import scan_screenshot
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
logger = logging.getLogger("oneclick_telegram_bot")

VT_API_KEY = os.environ.get("ONECLICK_VT_API_KEY")

VERDICT_EMOJI = {
    "Likely Safe": "🟢", "Suspicious": "🟡", "Phishing / Malicious": "🔴",
    "Known Threat": "🔴", "UPI Payment Request": "💸", "UPI Payment Request - REPORTED VPA": "🚨",
}


# =============================================================================
# Pure reply-building logic (no Telegram-specific code - fully unit testable)
# =============================================================================

def build_scan_url_reply(url: str) -> str:
    result = scan_url(url, vt_api_key=VT_API_KEY)
    database.save_url_scan(
        url=result["url"], verdict=result["label"],
        risk_score=result["score"], reasons=result["reasons"],
    )
    emoji = VERDICT_EMOJI.get(result["label"], "⚪")
    lines = [f"{emoji} *{result['label']}* — {result['score']}%", f"`{result['url']}`", ""]
    for reason in result["reasons"][:6]:
        lines.append(f"• {reason}")
    lines.append("")
    lines.append("_This is a flag, not an action — nothing was blocked or deleted. Review it yourself._")
    return "\n".join(lines)


def build_message_reply(text: str) -> str:
    """Handles a forwarded plain-text SMS/email/WhatsApp message: extracts
    and scans any URLs, redacts any OTP/codes, and flags scam-script patterns."""
    sections = []

    redaction = redact_message(text)
    if redaction["codes_hidden"] > 0:
        sections.append(
            f"🔒 Hid {redaction['codes_hidden']} OTP/code-like value(s) "
            f"(triggered by: {', '.join(redaction['keywords_matched'])}). "
            f"Never share OTPs with anyone, including \"bank staff\"."
        )

    scam_patterns = detect_scam_patterns(text)
    if scam_patterns:
        sections.append("🚩 *Matches known scam pattern(s):*")
        for p in scam_patterns:
            sections.append(f"  • *{p['category']}* — {p['explanation']}")

    urls = extract_urls_from_text(text)
    if urls:
        sections.append(f"🔗 Found {len(urls)} link(s):")
        for url in urls[:5]:  # cap to keep the reply readable
            result = scan_url(url, vt_api_key=VT_API_KEY)
            database.save_url_scan(
                url=result["url"], verdict=result["label"],
                risk_score=result["score"], reasons=result["reasons"],
            )
            emoji = VERDICT_EMOJI.get(result["label"], "⚪")
            sections.append(f"  {emoji} `{url}` — *{result['label']}* ({result['score']}%)")

    if not sections:
        return "✅ No OTPs, scam patterns, or links detected in this message."

    sections.append("\n_Flag-only — nothing was blocked, deleted, or reported automatically._")
    return "\n".join(sections)


def build_number_check_reply(number: str) -> str:
    r = check_phone_number(number)
    if r["is_reported"]:
        note = f"\n{r['note']}" if r["note"] else ""
        return f"⚠️ Reported {r['report_count']} time(s) — category: *{r['category']}*{note}"
    return "ℹ️ Not found in the local report list. This means \"not yet reported\", not \"verified safe\"."


def build_upi_check_reply(vpa: str) -> str:
    r = check_upi_id(vpa)
    if r["is_reported"]:
        note = f"\n{r['note']}" if r["note"] else ""
        return f"⚠️ Reported {r['report_count']} time(s) — category: *{r['category']}*{note}"
    return "ℹ️ Not found in the local report list. This means \"not yet reported\", not \"verified safe\"."


def build_photo_reply(image_path: str) -> str:
    """Handles a forwarded photo: tries QR decoding first (common case for
    payment/quishing QR codes), falls back to OCR (screenshot of a scam
    message) if no QR code is found."""
    if QR_AVAILABLE:
        qr_result = scan_qr_image(image_path, vt_api_key=VT_API_KEY)
        if qr_result["found"]:
            lines = [f"📷 Decoded {len(qr_result['payloads'])} QR code(s):"]
            for url_result in qr_result["url_results"]:
                emoji = VERDICT_EMOJI.get(url_result["label"], "⚪")
                lines.append(f"{emoji} *{url_result['label']}*")
                for reason in url_result["reasons"][:4]:
                    lines.append(f"  • {reason}")
            lines.append("\n_Flag-only — review before scanning/paying._")
            return "\n".join(lines)

    if OCR_AVAILABLE:
        ocr_result = scan_screenshot(image_path, vt_api_key=VT_API_KEY)
        if ocr_result["raw_text"].strip():
            return build_message_reply(ocr_result["raw_text"])

    missing = []
    if not QR_AVAILABLE:
        missing.append("QR decoding (pyzbar/libzbar0)")
    if not OCR_AVAILABLE:
        missing.append("OCR (pytesseract/tesseract-ocr)")
    if missing:
        return f"⚠️ Couldn't process this image — missing: {', '.join(missing)}. Run `python3 doctor.py` on the server."
    return "🤷 No QR code or readable text found in this image."


# =============================================================================
# Telegram wiring (thin - just calls the functions above)
# =============================================================================

def _build_application():
    """Deferred import + construction so this module can be imported (and its
    pure logic functions tested) without python-telegram-bot's Application
    machinery needing a valid token."""
    from telegram import Update
    from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

    token = os.environ.get("ONECLICK_TELEGRAM_TOKEN")
    if not token:
        raise RuntimeError(
            "ONECLICK_TELEGRAM_TOKEN environment variable not set. "
            "Get a token from @BotFather on Telegram, then: export ONECLICK_TELEGRAM_TOKEN=..."
        )

    async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "🛡️ *OneClick Bot*\n\n"
            "Forward me a suspicious message, link, QR code, or screenshot and I'll check it.\n\n"
            "Commands:\n"
            "/scan <url> — check a specific link\n"
            "/checknumber <number> — check a phone number against reported scams\n"
            "/checkupi <upi_id> — check a UPI ID against reported scams\n\n"
            "I only ever *flag* things — I never block, delete, or report anything on my own.",
            parse_mode="Markdown",
        )

    async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not context.args:
            await update.message.reply_text("Usage: /scan <url>")
            return
        reply = build_scan_url_reply(context.args[0])
        await update.message.reply_text(reply, parse_mode="Markdown")

    async def checknumber_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not context.args:
            await update.message.reply_text("Usage: /checknumber <number>")
            return
        reply = build_number_check_reply(context.args[0])
        await update.message.reply_text(reply, parse_mode="Markdown")

    async def checkupi_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not context.args:
            await update.message.reply_text("Usage: /checkupi <upi_id>")
            return
        reply = build_upi_check_reply(context.args[0])
        await update.message.reply_text(reply, parse_mode="Markdown")

    async def text_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        reply = build_message_reply(update.message.text)
        await update.message.reply_text(reply, parse_mode="Markdown")

    async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        photo = update.message.photo[-1]  # largest resolution
        tg_file = await photo.get_file()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
            await tg_file.download_to_drive(tmp.name)
            tmp_path = tmp.name
        try:
            reply = build_photo_reply(tmp_path)
        finally:
            os.unlink(tmp_path)
        await update.message.reply_text(reply, parse_mode="Markdown")

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("scan", scan_cmd))
    app.add_handler(CommandHandler("checknumber", checknumber_cmd))
    app.add_handler(CommandHandler("checkupi", checkupi_cmd))
    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_message_handler))
    return app


def main():
    app = _build_application()
    logger.info("OneClick Telegram bot starting (polling mode)...")
    app.run_polling()


if __name__ == "__main__":
    main()

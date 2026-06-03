import pytest
from migate.notifications.telegram import TelegramNotifier


def test_telegram_notifier_init_defaults():
    notifier = TelegramNotifier()
    assert notifier.bot_token == ""
    assert notifier.chat_id == ""


def test_telegram_notifier_init_with_values():
    notifier = TelegramNotifier(bot_token="123:ABC", chat_id="999")
    assert notifier.bot_token == "123:ABC"
    assert notifier.chat_id == "999"


def test_telegram_notifier_enabled_when_both_set():
    notifier = TelegramNotifier(bot_token="123:ABC", chat_id="999")
    assert notifier.enabled is True


def test_telegram_notifier_disabled_when_empty():
    notifier = TelegramNotifier()
    assert notifier.enabled is False


def test_telegram_notifier_disabled_when_only_token():
    notifier = TelegramNotifier(bot_token="123:ABC")
    assert notifier.enabled is False


def test_telegram_notifier_disabled_when_only_chat_id():
    notifier = TelegramNotifier(chat_id="999")
    assert notifier.enabled is False


@pytest.mark.asyncio
async def test_telegram_notifier_send_returns_false_when_disabled():
    notifier = TelegramNotifier()
    result = await notifier.send("test")
    assert result is False


@pytest.mark.asyncio
async def test_telegram_notifier_send_returns_false_on_invalid_token():
    notifier = TelegramNotifier(bot_token="invalid:token", chat_id="999")
    result = await notifier.send("test")
    # Should fail because token is invalid, but shouldn't raise
    assert result is False

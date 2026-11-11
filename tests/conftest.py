"""Pytest safety guards preventing unmocked webcam, GUI, network downloads, or stdin blocking."""

import os
import pytest


@pytest.fixture(autouse=True)
def _block_interactive_and_network_calls(monkeypatch):
    """Ensure automated tests never touch real webcam, GUI windows, downloads, or stdin."""
    monkeypatch.setenv("OMNIHERMES_TEST_MODE", "1")

    def _deny_webcam(*args, **kwargs):
        raise RuntimeError("Tests must not open the real webcam (cv2.VideoCapture)")

    def _deny_window(*args, **kwargs):
        raise RuntimeError("Tests must not open a real GUI window (tkinter.Tk)")

    def _deny_download(*args, **kwargs):
        raise RuntimeError("Tests must not download models or make network requests (urlopen)")

    def _deny_input(*args, **kwargs):
        raise RuntimeError("Tests must not wait for console input (input)")

    try:
        import cv2
        monkeypatch.setattr(cv2, "VideoCapture", _deny_webcam)
    except ImportError:
        pass

    try:
        import tkinter
        monkeypatch.setattr(tkinter, "Tk", _deny_window)
    except ImportError:
        pass

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _deny_download)
    monkeypatch.setattr("builtins.input", _deny_input)

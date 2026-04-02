"""
Python decorator for guarding function inputs against steganography.

Usage:
    from stegoff.guard import steg_guard

    @steg_guard
    def process_user_message(text: str) -> str:
        # text is guaranteed clean by the time it reaches here
        return llm.generate(text)

    @steg_guard(block=True, scan_kwargs=["prompt", "context"])
    def call_llm(prompt: str, context: str, temperature: float = 0.7):
        # both prompt and context are scanned and stripped
        return llm.generate(prompt, context=context, temperature=temperature)

    @steg_guard(on_detect="raise")
    def strict_handler(text: str):
        # raises StegDetected if any steg found
        pass
"""

from __future__ import annotations

import functools
import inspect
from typing import Callable

from stegoff.orchestrator import scan_text
from stegoff.cli import _strip_steg_chars
from stegoff.report import ScanReport


class StegDetected(Exception):
    """Raised when steganographic content is detected and mode is 'raise'."""
    def __init__(self, report: ScanReport):
        self.report = report
        super().__init__(report.summary())


class PromptInjectionDetected(StegDetected):
    """Raised specifically when a prompt injection payload is found."""
    pass


def steg_guard(
    func: Callable | None = None,
    *,
    scan_kwargs: list[str] | None = None,
    on_detect: str = "strip",   # "strip", "raise", "log"
    block_injection: bool = True,
):
    """
    Decorator that scans string arguments for steganographic content.

    Args:
        scan_kwargs: Specific keyword argument names to scan.
                     If None, scans all string args.
        on_detect: What to do when steg is found:
                   "strip"  - remove steg chars, pass clean text (default)
                   "raise"  - raise StegDetected exception
                   "log"    - print warning, pass original text
        block_injection: Always raise PromptInjectionDetected regardless
                        of on_detect setting.
    """
    def decorator(fn: Callable) -> Callable:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            for param_name, value in bound.arguments.items():
                if not isinstance(value, str):
                    continue
                if scan_kwargs and param_name not in scan_kwargs:
                    continue

                report = scan_text(value, source=f"arg:{param_name}")

                if report.clean:
                    continue

                # Prompt injection always blocks
                if report.prompt_injection_detected and block_injection:
                    raise PromptInjectionDetected(report)

                if on_detect == "raise":
                    raise StegDetected(report)
                elif on_detect == "strip":
                    bound.arguments[param_name] = _strip_steg_chars(value)
                elif on_detect == "log":
                    import sys
                    print(
                        f"[stegoff] WARNING: steg detected in {param_name}: "
                        f"{report.finding_count} findings",
                        file=sys.stderr,
                    )

            return fn(*bound.args, **bound.kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            for param_name, value in bound.arguments.items():
                if not isinstance(value, str):
                    continue
                if scan_kwargs and param_name not in scan_kwargs:
                    continue

                report = scan_text(value, source=f"arg:{param_name}")

                if report.clean:
                    continue

                if report.prompt_injection_detected and block_injection:
                    raise PromptInjectionDetected(report)

                if on_detect == "raise":
                    raise StegDetected(report)
                elif on_detect == "strip":
                    bound.arguments[param_name] = _strip_steg_chars(value)
                elif on_detect == "log":
                    import sys
                    print(
                        f"[stegoff] WARNING: steg detected in {param_name}: "
                        f"{report.finding_count} findings",
                        file=sys.stderr,
                    )

            return await fn(*bound.args, **bound.kwargs)

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return wrapper

    if func is not None:
        return decorator(func)
    return decorator

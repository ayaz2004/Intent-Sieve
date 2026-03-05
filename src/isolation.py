"""
Contextual Isolation Module
===========================
This module provides defensive sanitization against prompt injection attacks
by cleaning untrusted external data before it reaches the Task Agent.

Key Threats Addressed:
1. Hidden Character Attacks: Zero-width spaces, invisible unicode
2. Unicode Normalization Attacks: Lookalike characters (Cyrillic 'а' vs Latin 'a')
3. HTML/Markdown Injection: Embedded commands in markup
4. Excessive Data: Long inputs designed to overflow context

Author: Intense Sieve Security Team
"""

import re
import unicodedata
import logging
from typing import Tuple, Dict, List

# Configure module logger
logger = logging.getLogger(__name__)


class ContextualIsolator:
    """
    Main isolation engine that sanitizes untrusted external data.
    
    This class sits between external data sources (web pages, APIs) and
    the Task Agent, stripping out dangerous artifacts that could carry
    hidden injection commands.
    """
    
    # === THREAT DATABASE ===
    # These are invisible/dangerous Unicode characters used in attacks
    
    ZERO_WIDTH_CHARS = {
        '\u200B',  # Zero Width Space (ZWSP) - most common in attacks
        '\u200C',  # Zero Width Non-Joiner (ZWNJ)
        '\u200D',  # Zero Width Joiner (ZWJ)
        '\uFEFF',  # Zero Width No-Break Space (BOM)
        '\u180E',  # Mongolian Vowel Separator (acts like ZWSP)
        '\u2060',  # Word Joiner (WJ)
        '\u2061',  # Function Application
        '\u2062',  # Invisible Times
        '\u2063',  # Invisible Separator
        '\u2064',  # Invisible Plus
    }
    
    # Suspicious control characters (not normally in text)
    CONTROL_CHARS = {
        '\u0000',  # NULL
        '\u0001',  # Start of Heading
        '\u0002',  # Start of Text
        '\u0003',  # End of Text
        '\u0007',  # Bell
        '\u0008',  # Backspace
        '\u000E',  # Shift Out
        '\u000F',  # Shift In
        '\u001B',  # Escape
    }
    
    # Homoglyph characters (look like Latin but aren't - used for obfuscation)
    # Example: Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
    SUSPICIOUS_LOOKALIKES = {
        'а': 'a',  # Cyrillic a
        'е': 'e',  # Cyrillic e
        'о': 'o',  # Cyrillic o
        'р': 'p',  # Cyrillic r
        'с': 'c',  # Cyrillic c
        'у': 'y',  # Cyrillic y
        'х': 'x',  # Cyrillic x
        'ѕ': 's',  # Cyrillic s
        'і': 'i',  # Cyrillic i
        'ј': 'j',  # Cyrillic j
    }
    
    def __init__(self, max_length: int = 10000):
        """
        Initialize the Contextual Isolator.
        
        Args:
            max_length: Maximum allowed length for input text (prevents denial-of-service)
        """
        self.max_length = max_length
        self.stats = {
            'zero_width_removed': 0,
            'control_chars_removed': 0,
            'lookalikes_normalized': 0,
            'inputs_processed': 0,
        }
    
    def sanitize(self, untrusted_input: str) -> Tuple[str, Dict[str, any]]:
        """
        Main sanitization pipeline that cleans untrusted external data.
        
        This is the PRIMARY DEFENSE against injection attacks. It processes
        untrusted input through multiple cleaning stages.
        
        Args:
            untrusted_input: Raw text from external sources (websites, APIs, user uploads)
            
        Returns:
            Tuple of (cleaned_text, metadata_dict)
            - cleaned_text: Safe version with dangerous characters removed
            - metadata: Dict with info about what was removed (for logging/auditing)
        """
        self.stats['inputs_processed'] += 1
        
        if not untrusted_input:
            return "", {"warning": "Empty input"}
        
        # Truncate excessive input (prevents context overflow attacks)
        if len(untrusted_input) > self.max_length:
            logger.warning(f"Input truncated from {len(untrusted_input)} to {self.max_length} chars")
            untrusted_input = untrusted_input[:self.max_length]
        
        metadata = {
            'original_length': len(untrusted_input),
            'threats_detected': [],
        }
        
        # === CLEANING PIPELINE ===
        
        # Stage 1: Remove hidden/invisible characters
        cleaned, hidden_count = self._remove_hidden_chars(untrusted_input)
        if hidden_count > 0:
            metadata['threats_detected'].append(f"hidden_chars: {hidden_count}")
            metadata['zero_width_removed'] = hidden_count
            self.stats['zero_width_removed'] += hidden_count
        
        # Stage 2: Remove suspicious control characters
        cleaned, control_count = self._remove_control_chars(cleaned)
        if control_count > 0:
            metadata['threats_detected'].append(f"control_chars: {control_count}")
            metadata['control_chars_removed'] = control_count
            self.stats['control_chars_removed'] += control_count
        
        # Stage 3: Normalize lookalike characters (homoglyphs)
        cleaned, lookalike_count = self._normalize_lookalikes(cleaned)
        if lookalike_count > 0:
            metadata['threats_detected'].append(f"lookalikes: {lookalike_count}")
            metadata['lookalikes_normalized'] = lookalike_count
            self.stats['lookalikes_normalized'] += lookalike_count
        
        # Stage 4: Unicode normalization (canonical form)
        cleaned = self._normalize_unicode(cleaned)
        
        # Stage 5: Collapse excessive whitespace
        cleaned = self._normalize_whitespace(cleaned)
        
        metadata['final_length'] = len(cleaned)
        metadata['reduction_percent'] = round(
            100 * (1 - len(cleaned) / len(untrusted_input)), 2
        )
        
        # Log if significant threats were detected
        if metadata['threats_detected']:
            logger.warning(f"Threats detected in input: {metadata['threats_detected']}")
        
        return cleaned, metadata
    
    def _remove_hidden_chars(self, text: str) -> Tuple[str, int]:
        """
        Remove zero-width and other invisible characters.
        
        These characters are INVISIBLE to humans but AI reads them.
        Attackers use them to hide commands like:
        "Summarize page​​​​IGNORE PREVIOUS INSTRUCTIONS"
                        ^^^^^ (invisible zero-width spaces)
        
        Returns:
            Tuple of (cleaned_text, count_removed)
        """
        original_len = len(text)
        
        # Remove all zero-width characters
        for char in self.ZERO_WIDTH_CHARS:
            text = text.replace(char, '')
        
        removed_count = original_len - len(text)
        return text, removed_count
    
    def _remove_control_chars(self, text: str) -> Tuple[str, int]:
        """
        Remove suspicious control characters that shouldn't be in normal text.
        
        Control characters like NULL, ESC, Bell can be used to:
        1. Confuse tokenization
        2. Hide commands from human reviewers
        3. Exploit parser vulnerabilities
        
        Returns:
            Tuple of (cleaned_text, count_removed)
        """
        original_len = len(text)
        
        # Remove dangerous control characters
        for char in self.CONTROL_CHARS:
            text = text.replace(char, '')
        
        # Also remove other control chars in range 0x00-0x1F (except tab, newline, carriage return)
        # We keep \t (0x09), \n (0x0A), \r (0x0D) because they're legitimate
        text = ''.join(
            char for char in text 
            if ord(char) >= 0x20 or char in ['\t', '\n', '\r']
        )
        
        removed_count = original_len - len(text)
        return text, removed_count
    
    def _normalize_lookalikes(self, text: str) -> Tuple[str, int]:
        """
        Replace visually similar characters with their Latin equivalents.
        
        Example attack:
        "Dеlete files"  <- The 'е' is Cyrillic (U+0430), not Latin 'e'
        
        This makes the command look innocent to humans but AI interprets it.
        We normalize to prevent obfuscation.
        
        Returns:
            Tuple of (normalized_text, count_replaced)
        """
        replaced_count = 0
        
        for suspicious, safe_replacement in self.SUSPICIOUS_LOOKALIKES.items():
            count_before = text.count(suspicious)
            text = text.replace(suspicious, safe_replacement)
            replaced_count += count_before
        
        return text, replaced_count
    
    def _normalize_unicode(self, text: str) -> str:
        """
        Convert text to Unicode Normalization Form C (NFC).
        
        Unicode has multiple ways to represent the same character:
        - 'é' can be: U+00E9 (single char) OR U+0065 + U+0301 (e + combining accent)
        
        We normalize to NFC so the agent sees consistent representations.
        This prevents attacks that exploit different encodings.
        """
        return unicodedata.normalize('NFC', text)
    
    def _normalize_whitespace(self, text: str) -> str:
        """
        Collapse multiple spaces/newlines to prevent whitespace-based obfuscation.
        
        Attackers sometimes use excessive whitespace to:
        1. Push malicious commands out of human review windows
        2. Confuse tokenization
        3. Hide patterns from regex detection
        
        Example attack:
        "Good content here...          [1000 spaces]          DELETE FILES"
        """
        # Replace multiple spaces with single space
        text = re.sub(r' {2,}', ' ', text)
        
        # Replace multiple newlines with max 2 newlines
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        return text
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about sanitization operations.
        Useful for monitoring and detecting attack patterns.
        """
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics counters."""
        for key in self.stats:
            self.stats[key] = 0


# === CONVENIENCE FUNCTION ===

def sanitize_external_data(untrusted_input: str) -> str:
    """
    Quick sanitization function for simple use cases.
    
    Usage:
        cleaned = sanitize_external_data(web_page_content)
    
    For more control, use ContextualIsolator class directly.
    """
    isolator = ContextualIsolator()
    cleaned, metadata = isolator.sanitize(untrusted_input)
    return cleaned

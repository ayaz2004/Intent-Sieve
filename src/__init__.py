"""
Intense Sieve Package
A security framework for AI agents with multi-layer validation.
"""

# Core modules can be imported independently
# isolation and detectors don't require heavy dependencies
# agent, sieve, and tools require langchain_ollama

__all__ = [
    'TaskAgent',
    'IntentSieve',
    'available_tools',
    'fetch_web_page',
    'delete_system_files',
    'read_local_file',
    'ContextualIsolator',
    'InjectionDetector',
]

# Lazy imports to avoid loading heavy dependencies when not needed
def __getattr__(name):
    if name == 'TaskAgent':
        from .agent import TaskAgent
        return TaskAgent
    elif name == 'IntentSieve':
        from .sieve import IntentSieve
        return IntentSieve
    elif name in ['available_tools', 'fetch_web_page', 'delete_system_files', 'read_local_file']:
        from . import tools
        return getattr(tools, name)
    elif name == 'ContextualIsolator':
        from .isolation import ContextualIsolator
        return ContextualIsolator
    elif name == 'InjectionDetector':
        from .detectors import InjectionDetector
        return InjectionDetector
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

"""LangChain tools wrapper for AgentShield prototype.

This module provides helpers to wrap LangChain `Tool` objects so that any
call to a tool is routed through the local `shield` policy engine and notifier
before execution.

Usage (example):

```python
# create or import your tools as usual
from langchain.tools import Tool
from agentshield.integrations.langchain_wrapper import wrap_langchain_tools

# suppose you have a Tool instance
# tool = Tool.from_function(func=read_file, name="read_file")
# or any object with a .run (sync) or .arun (async) callable

wrap_langchain_tools([tool], agent_name='research_bot')

# then pass the wrapped tools into your Agent/AgentExecutor
```

Notes:
- This is a best-effort wrapper for common LangChain tool shapes. If you use
  custom tool classes, ensure they expose `.run` (sync) or `.arun` (async).
- The wrapper mutates the tool objects in-place.
"""
from functools import wraps
from typing import Iterable

from agentshield import shield


def _tool_display_name(tool):
    return getattr(tool, 'name', None) or getattr(tool, 'tool_name', None) or tool.__class__.__name__


def wrap_langchain_tools(tools: Iterable, agent_name: str = 'unknown'):
    """Wrap a list of LangChain tool objects so their execution is policy-checked.

    Modifies tools in-place and also returns the list for convenience.
    """
    for tool in tools:
        name = _tool_display_name(tool)

        # wrap synchronous run if present
        if hasattr(tool, 'run'):
            orig_run = tool.run

            @wraps(orig_run)
            def _run(*args, _orig_run=orig_run, _name=name, **kwargs):
                action = {
                    'type': 'tool',
                    'subtype': 'langchain_tool',
                    'tool_name': _name,
                    'agent': agent_name,
                    'input_args': args,
                    'input_kwargs': kwargs,
                }
                allowed = shield.evaluate_action(action)
                if allowed:
                    return _orig_run(*args, **kwargs)
                raise PermissionError(f"AgentShield blocked tool {_name}")

            tool.run = _run

        # wrap async arun if present
        if hasattr(tool, 'arun'):
            orig_arun = tool.arun

            @wraps(orig_arun)
            async def _arun(*args, _orig_arun=orig_arun, _name=name, **kwargs):
                action = {
                    'type': 'tool',
                    'subtype': 'langchain_tool',
                    'tool_name': _name,
                    'agent': agent_name,
                    'input_args': args,
                    'input_kwargs': kwargs,
                }
                allowed = shield.evaluate_action(action)
                if allowed:
                    return await _orig_arun(*args, **kwargs)
                raise PermissionError(f"AgentShield blocked tool {_name}")

            tool.arun = _arun

    return list(tools)

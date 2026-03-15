"""Generic agent wrapper utilities for AgentShield prototype.

This module provides helpers to wrap plain callables and object attributes (e.g.
methods used as tools) so calls are evaluated by `shield` before executing.

Use cases:
 - Custom Python agents with a dict of tool functions
 - Wrapping methods on agent instances

Example:

```python
from agentshield.integrations.generic_agent_wrapper import wrap_functions_map

functions = {'read_file': read_file_fn, 'http_post': http_post_fn}
wrapped = wrap_functions_map(functions, agent_name='research_agent')
# now use wrapped['read_file'](...) and calls will go through AgentShield
```
"""
from functools import wraps
from typing import Callable, Dict

from agentshield import shield


def wrap_functions_map(functions: Dict[str, Callable], agent_name: str = 'unknown') -> Dict[str, Callable]:
    """Return a new dict mapping names to wrapped callables that are policy-checked.

    The original dict is not mutated.
    """
    wrapped = {}

    for name, fn in functions.items():
        if callable(fn):
            orig = fn

            @wraps(orig)
            def _wrapper(*args, _orig=orig, _name=name, **kwargs):
                action = {
                    'type': 'tool',
                    'subtype': 'generic_function',
                    'tool_name': _name,
                    'agent': agent_name,
                    'input_args': args,
                    'input_kwargs': kwargs,
                }
                allowed = shield.evaluate_action(action)
                if allowed:
                    return _orig(*args, **kwargs)
                raise PermissionError(f"AgentShield blocked function {_name}")

            wrapped[name] = _wrapper
        else:
            # non-callable pass-through
            wrapped[name] = fn

    return wrapped


def wrap_instance_methods(instance, method_names, agent_name: str = 'unknown'):
    """Wrap named methods on an instance in-place. Useful for agent objects.

    Example:
        wrap_instance_methods(agent, ['read', 'write'], agent_name='bot1')
    """
    for name in method_names:
        if hasattr(instance, name):
            orig = getattr(instance, name)
            if callable(orig):

                @wraps(orig)
                def _m(*args, _orig=orig, _name=name, **kwargs):
                    action = {
                        'type': 'tool',
                        'subtype': 'instance_method',
                        'tool_name': _name,
                        'agent': agent_name,
                        'input_args': args,
                        'input_kwargs': kwargs,
                    }
                    allowed = shield.evaluate_action(action)
                    if allowed:
                        return _orig(*args, **kwargs)
                    raise PermissionError(f"AgentShield blocked method {_name}")

                setattr(instance, name, _m)
    return instance

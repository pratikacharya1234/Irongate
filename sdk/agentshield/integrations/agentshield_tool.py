"""LangChain Tool factory that wraps functions with AgentShield protection.

This is a small convenience helper so developers can turn an ordinary
callable into a LangChain Tool which first asks `shield.evaluate_action`
before executing the underlying function.

This file is intentionally minimal and optional — it does not modify any
existing wrappers or runtime behavior.
"""

class AgentshieldTool:
    @staticmethod
    def from_function(func, name=None, description=None, agent="default_agent"):
        """
        Create a LangChain Tool that is automatically protected by AgentShield.

        Parameters:
          func: callable to expose as a Tool
          name: optional tool name (defaults to func.__name__)
          description: optional description for the Tool
          agent: agent identifier to attach to the action
        """

        # keep imports local so this helper is optional and won't fail at import
        from langchain.tools import Tool
        from agentshield import shield
        import inspect

        tool_name = name or getattr(func, "__name__", "unnamed_tool")

        is_async = inspect.iscoroutinefunction(func)

        def wrapped(*args, **kwargs):
            action = {
                "type": "tool",
                "tool_name": tool_name,
                "agent": agent,
            }

            allowed = shield.evaluate_action(action)

            if not allowed:
                raise PermissionError(f"AgentShield blocked tool: {tool_name}")

            return func(*args, **kwargs)

        async def wrapped_async(*args, **kwargs):
            action = {
                "type": "tool",
                "tool_name": tool_name,
                "agent": agent,
            }

            allowed = shield.evaluate_action(action)

            if not allowed:
                raise PermissionError(f"AgentShield blocked tool: {tool_name}")

            return await func(*args, **kwargs)

        # Create Tool with coroutine if the underlying function is async
        if is_async:
            return Tool(
                name=tool_name,
                description=description or (func.__doc__ or ""),
                func=wrapped_async,
                coroutine=wrapped_async,
            )

        return Tool(
            name=tool_name,
            description=description or (func.__doc__ or ""),
            func=wrapped,
        )

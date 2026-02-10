from src.agent import TaskAgent
from src.sieve import IntentSieve
from src.tools import available_tools
from langchain_core.messages import HumanMessage, ToolMessage, SystemMessage

def run_pipeline(user_query):
    print(f"\n{'-'*50}\n>>> USER QUERY: {user_query}")
    
    agent = TaskAgent()
    sieve = IntentSieve()
    tools_map = {t.name: t for t in available_tools}
    
    # Using a SystemMessage helps Llama 3.1 understand its role better
    messages = [
        SystemMessage(content="You are a secure Agentic AI. If the 'Intent Sieve' blocks your action, you must stop all tool calls and explain the security violation to the user."),
        HumanMessage(content=user_query)
    ]
    
    is_blocked = False  # Track if we hit a security wall

    for step in range(3):
        ai_msg = agent.plan(messages)
        messages.append(ai_msg)

        if not ai_msg.tool_calls or is_blocked:
            break 

        for tool_call in ai_msg.tool_calls:
            authorized, reason = sieve.validate(user_query, tool_call)
            
            if authorized:
                print(f"[SYSTEM] Executing: {tool_call['name']}")
                result = tools_map[tool_call['name']].invoke(tool_call['args'])
                messages.append(ToolMessage(content=str(result), tool_call_id=tool_call['id']))
            else:
                print(f"[SYSTEM] BLOCKED: {reason}")
                # We feed the error back and set the block flag
                messages.append(ToolMessage(content=f"CRITICAL SECURITY ERROR: {reason}", tool_call_id=tool_call['id']))
                is_blocked = True 
                break # Stop processing other tool calls in this step

    # FINAL RESPONSE LOGIC
    if is_blocked:
        # If blocked, we force the agent to explain the "Guardrail Intervention"
        messages.append(HumanMessage(content="The previous action was blocked by the Intent Sieve. Explain exactly why this was a security risk based on my original request."))
    
    final_response = agent.plan(messages)
    
    # If the model still tries to call a tool, we don't show the tool code, we show a clean message
    if final_response.tool_calls and is_blocked:
        output_text = "ACCESS DENIED: The Intent Sieve neutralized a 'Semantic Hijacking' attempt. The agent tried to execute an unauthorized destructive command found in external data."
    else:
        output_text = final_response.content if final_response.content else "Summary: Task completed, but some actions were restricted by security policy."

    print(f"\nFINAL RESPONSE: {output_text}")
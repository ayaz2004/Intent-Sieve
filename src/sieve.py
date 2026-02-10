import logging
import time
import os
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

class IntentSieve:
    def __init__(self):
        # We still use Llama Guard for the 'Neuro' reasoning
        self.guard = ChatOllama(model="llama-guard3:8b", temperature=0)

    def validate(self, original_intent, tool_call):
        start_time = time.time()
        action = tool_call['name']
        args = tool_call['args']
        
        print(f"\n[SIEVE] Analyzing action: {action}...")

        # --- LAYER 1: SYMBOLIC (HARD RULES) ---
        # Rule: Only block 'delete' if 'delete' wasn't in the original prompt.
        is_destructive = "delete" in action.lower()
        is_authorized = "delete" in original_intent.lower()

        if is_destructive and not is_authorized:
            latency = time.time() - start_time
            msg = f"REJECTED: Semantic Drift! (Action: {action} not in Intent). Time: {latency:.2f}s"
            logging.warning(msg)
            return False, msg

        # --- LAYER 2: NEURAL (LLAMA GUARD 3) ---
        # We ONLY run the Neural check for high-risk actions. 
        # This allows 'fetch_web_page' to succeed so we can see the attack.
        if is_destructive:
            check_msg = f"User Intent: {original_intent}\nProposed Action: {action}({args})"
            response = self.guard.invoke([HumanMessage(content=check_msg)])
            
            if "unsafe" in response.content.lower():
                latency = time.time() - start_time
                return False, f"NEURAL BLOCK: Llama Guard flagged as unsafe. Time: {latency:.2f}s"

        # --- LAYER 3: CONTEXTUAL ISOLATION ---
        # If it's just reading a page, we allow it to proceed to see what happens.
        latency = time.time() - start_time
        logging.info(f"AUTHORIZED: {action} (Time: {latency:.2f}s)")
        return True, None
import logging
import time
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

class IntentSieve:
    def __init__(self):
        # Neural reasoning for high-risk validation
        self.guard = ChatOllama(model="llama-guard3:8b", temperature=0)
        
    def _is_argument_consistent(self, original_intent, tool_args):
        """
        Check if the tool arguments (like filenames or URLs) 
        actually appear or are implied in the original intent.
        """
        intent_lower = original_intent.lower()
        for val in tool_args.values():
            if str(val).lower() not in intent_lower:
                # Basic check: if the user didn't mention the target, it's suspicious
                return False
        return True

    def validate(self, original_intent, tool_call):
        start_time = time.time()
        action = tool_call['name']
        args = tool_call['args']
        
        print(f"\n[SIEVE] Analyzing action: {action}...")

        # --- LAYER 1: SYMBOLIC (Intent & Argument Matching) ---
        # Instead of just "delete", we check if the action AND the target match the intent
        is_destructive = any(word in action.lower() for word in ["delete", "remove", "clear"])
        
        if is_destructive:
            # Check if user actually asked to delete something
            intent_authorized = any(word in original_intent.lower() for word in ["delete", "remove", "clean"])
            # Check if the specific target in 'args' was mentioned
            args_authorized = self._is_argument_consistent(original_intent, args)

            if not (intent_authorized and args_authorized):
                latency = time.time() - start_time
                msg = f"REJECTED: Semantic Drift! Action '{action}' or target {args} not authorized. Time: {latency:.2f}s"
                logging.warning(msg)
                return False, msg

        # --- LAYER 2: NEURAL (Universal Guardrail) ---
        # Run Llama Guard for ALL tool calls to detect indirect prompt injections
        check_msg = f"User Intent: {original_intent}\nProposed Action: {action}({args})"
        response = self.guard.invoke([HumanMessage(content=check_msg)])
        
        if "unsafe" in response.content.lower():
            latency = time.time() - start_time
            return False, f"NEURAL BLOCK: Llama Guard flagged as unsafe. Time: {latency:.2f}s"

        latency = time.time() - start_time
        logging.info(f"AUTHORIZED: {action} (Time: {latency:.2f}s)")
        return True, None
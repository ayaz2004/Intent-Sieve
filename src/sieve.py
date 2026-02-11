import logging
import time
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

class IntentSieve:
    def __init__(self):
        # Neural reasoning for high-risk validation
        self.guard = ChatOllama(model="llama-guard3:8b", temperature=0)
        
    def _is_argument_consistent(self, original_intent, tool_args):
        intent_lower = original_intent.lower()
        for val in tool_args.values():
            # Simple heuristic: argument value must be present in intent
            if str(val).lower() not in intent_lower:
                return False
        return True

    def validate(self, original_intent, tool_call):
        """
        Returns a tuple: (STATUS, REASON)
        STATUS can be: "ALLOW", "BLOCK", "REVIEW"
        """
        start_time = time.time()
        action = tool_call['name']
        args = tool_call['args']
        
        print(f"\n[SIEVE] Analyzing action: {action}...")

        # --- LAYER 1: SYMBOLIC (Hallucination/Drift Check) ---
        # We ensure the model isn't inventing actions the user didn't ask for.
        is_destructive = any(word in action.lower() for word in ["delete", "remove", "clear"])
        
        if is_destructive:
            intent_authorized = any(word in original_intent.lower() for word in ["delete", "remove", "clean"])
            args_authorized = self._is_argument_consistent(original_intent, args)

            if not (intent_authorized and args_authorized):
                return "BLOCK", f"Semantic Drift! Action '{action}' not explicitly requested."

        # --- LAYER 2: NEURAL (Security Check) ---
        # Check for Prompt Injection or Jailbreaks
        check_msg = f"User Intent: {original_intent}\nProposed Action: {action}({args})"
        response = self.guard.invoke([HumanMessage(content=check_msg)])
        
        if "unsafe" in response.content.lower():
            return "BLOCK", "Llama Guard flagged as unsafe (Potential Injection)."

        # --- LAYER 3: RISK ASSESSMENT (Routing) ---
        # If we pass Layer 1 & 2, the action is 'valid', but might still be risky.
        # We route destructive actions to Human-in-the-Loop.
        
        if is_destructive:
            latency = time.time() - start_time
            logging.warning(f"REVIEW REQUIRED: {action} (Time: {latency:.2f}s)")
            return "REVIEW", "Destructive action detected."

        # If it's not destructive and passed safety checks, it's low risk.
        latency = time.time() - start_time
        logging.info(f"AUTHORIZED: {action} (Time: {latency:.2f}s)")
        return "ALLOW", "Low risk action."
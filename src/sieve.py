import logging
import time
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

# Import our new security modules
from .isolation import ContextualIsolator
from .detectors import InjectionDetector

class IntentSieve:
    def __init__(self):
        # Neural reasoning for high-risk validation
        self.guard = ChatOllama(model="llama-guard3:8b", temperature=0)
        
        # NEW: Add contextual isolation and detection layers
        self.isolator = ContextualIsolator(max_length=10000)
        self.detector = InjectionDetector(
            keyword_threshold=0.15,
            entropy_threshold=4.5,
            repetition_threshold=0.3
        )
        
    def _is_argument_consistent(self, original_intent, tool_args):
        """
        Check if tool arguments are reasonable given the user's intent.
        
        We allow agent-generated metadata (like 'reason' fields) and focus on
        validating that file paths or critical arguments match the intent.
        """
        intent_lower = original_intent.lower()
        
        # For destructive actions, check critical arguments only
        # Skip metadata like 'reason' which the agent adds
        critical_args = []
        for key, val in tool_args.items():
            # Skip agent-generated metadata fields
            if key.lower() in ['reason', 'justification', 'explanation']:
                continue
            critical_args.append(str(val))
        
        # If no critical arguments, it's likely a general destructive command
        # which should be caught by semantic check (e.g., "delete everything")
        if not critical_args:
            return True
        
        # Otherwise, at least one critical argument should relate to the intent
        for arg in critical_args:
            # Check if argument concept is in intent (flexible matching)
            arg_words = arg.lower().split()
            if any(word in intent_lower for word in arg_words if len(word) > 3):
                return True
        
        return False

    def validate(self, original_intent, tool_call):
        """
        Enhanced validation with multi-layer security.
        
        Returns a tuple: (STATUS, REASON)
        STATUS can be: "ALLOW", "BLOCK", "REVIEW"
        """
        start_time = time.time()
        action = tool_call['name']
        args = tool_call['args']
        
        print(f"\n[SIEVE] Analyzing action: {action}...")

        # --- LAYER 0: CONTEXTUAL ISOLATION (NEW!) ---
        # Sanitize the user intent to remove hidden attacks
        cleaned_intent, isolation_metadata = self.isolator.sanitize(original_intent)
        
        # If sanitization detected threats, log them
        if isolation_metadata['threats_detected']:
            logging.warning(f"[ISOLATION] Threats cleaned: {isolation_metadata['threats_detected']}")
        
        # --- LAYER 0.5: INJECTION DETECTION (NEW!) ---
        # Analyze the cleaned intent for injection patterns
        threats, injection_risk = self.detector.analyze(cleaned_intent)
        
        # If high injection risk detected, BLOCK immediately
        if injection_risk > 0.7:
            threat_details = ', '.join([t.threat_type for t in threats])
            return "BLOCK", f"High injection risk detected ({injection_risk:.2f}): {threat_details}"
        
        # If medium injection risk, flag for additional scrutiny
        if injection_risk > 0.4:
            logging.warning(f"[DETECTOR] Medium injection risk: {injection_risk:.2f}")
        
        # Use cleaned intent for remaining validation
        original_intent = cleaned_intent

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
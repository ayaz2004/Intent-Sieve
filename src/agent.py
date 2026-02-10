from langchain_ollama import ChatOllama
from .tools import available_tools

class TaskAgent:
    def __init__(self):
        # Bind the tools to the model
        self.model = ChatOllama(model="llama3.1:8b", temperature=0).bind_tools(available_tools)

    def plan(self, messages):
        return self.model.invoke(messages)
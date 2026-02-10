@echo off
python -m venv venv
call .\venv\Scripts\activate
pip install -r requirements.txt
ollama pull llama3.1:8b
ollama pull llama-guard3:8b
echo Setup Complete.
pause
@echo off
set PYTHON_PATH="C:\Users\ayaz\anaconda3\python.exe"

echo Creating virtual environment using Anaconda Python...
%PYTHON_PATH% -m venv venv

echo Activating environment...
call .\venv\Scripts\activate

echo Upgrading pip...
python -m pip install --upgrade pip

echo Installing dependencies...
pip install -r requirement.txt

echo Pulling Ollama models...
ollama pull llama3.1:8b
ollama pull llama-guard3:8b

echo Setup Complete.
pause
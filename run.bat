@echo off

IF NOT EXIST .venv\Scripts\activate (
    echo [!] .venv not found. Run: python bootstrap.py
    exit /b 1
)

call .venv\Scripts\activate
python analyzer.py %*
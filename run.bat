@echo off

REM Check if the virtual environment already exists
if not exist "venv\" (
    echo Creating a virtual environment...
    python -m venv venv

    REM Activate the virtual environment
    call venv\Scripts\activate

    echo Installing the required packages...
    REM List all the required packages here
    pip install discord holehe httpx aiohttp
) else (
    REM Activate the virtual environment
    call venv\Scripts\activate
)

REM Run the bot
python main.py

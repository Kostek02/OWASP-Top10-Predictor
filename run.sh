#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
YELLOW='\033[1;33m'

echo -e "${GREEN}Setting up OWASP Top 10 Predictor...${NC}"

# Function to install with pip
install_with_pip() {
    echo -e "\n${GREEN}Creating Python virtual environment...${NC}"
    python3 -m venv venv
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create virtual environment. Please ensure python3-venv is installed.${NC}"
        exit 1
    fi
    
    # Activate virtual environment
    echo -e "\n${GREEN}Activating virtual environment...${NC}"
    source venv/bin/activate
    
    # Upgrade pip
    echo -e "\n${GREEN}Upgrading pip...${NC}"
    python -m pip install --upgrade pip
    
    # Install dependencies
    echo -e "\n${GREEN}Installing dependencies...${NC}"
    pip install -r requirements.txt
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install dependencies${NC}"
        exit 1
    fi
}

# Function to install with conda
install_with_conda() {
    ENV_NAME="owasp-predictor"
    echo -e "\n${GREEN}Creating conda environment...${NC}"
    
    # Remove existing environment if it exists
    conda env remove -n $ENV_NAME -y 2>/dev/null
    
    # Add conda-forge channel
    conda config --add channels conda-forge
    conda config --set channel_priority flexible
    
    # Create new environment with Python 3.11
    echo -e "\n${GREEN}Creating new conda environment with Python 3.11...${NC}"
    if ! conda create -n $ENV_NAME python=3.11 pip -y; then
        echo -e "${RED}Failed to create conda environment${NC}"
        exit 1
    fi
    
    # Activate environment
    echo -e "\n${GREEN}Activating conda environment...${NC}"
    source $(conda info --base)/etc/profile.d/conda.sh
    conda activate $ENV_NAME
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to activate conda environment${NC}"
        exit 1
    fi
    
    # Install core dependencies with conda
    echo -e "\n${GREEN}Installing core dependencies with conda...${NC}"
    if ! conda install -y \
        numpy=1.24.3 \
        pandas=1.5.3 \
        scikit-learn=1.2.2 \
        requests=2.31.0 \
        beautifulsoup4=4.12.2 \
        python-dotenv=1.0.0 \
        plotly=5.14.1 \
        nltk=3.8.1; then
        
        echo -e "${RED}Failed to install core conda packages${NC}"
        exit 1
    fi
    
    # Install PyTorch separately
    echo -e "\n${GREEN}Installing PyTorch...${NC}"
    if ! conda install -y pytorch=2.0.1 -c pytorch; then
        echo -e "${RED}Failed to install PyTorch${NC}"
        exit 1
    fi
    
    # Install remaining packages with pip
    echo -e "\n${GREEN}Installing additional dependencies with pip...${NC}"
    python -m pip install -r requirements.txt
}

# Check if conda exists and ask user which installation method to use
if command -v conda &> /dev/null; then
    echo -e "${YELLOW}Conda is available. Would you like to use conda for installation? (y/n)${NC}"
    read -p "" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_with_conda
    else
        install_with_pip
    fi
else
    echo -e "${YELLOW}Conda not found. Proceeding with pip installation...${NC}"
    install_with_pip
fi

# Create necessary directories
echo -e "\n${GREEN}Creating necessary directories...${NC}"
mkdir -p results data models logs

# Check if .env exists, if not copy from example
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        echo -e "\n${YELLOW}No .env file found. Creating from .env.example...${NC}"
        cp .env.example .env
        echo -e "${YELLOW}Please edit .env file with your API keys before running the analysis.${NC}"
        echo -e "${YELLOW}You need at least a GitHub token to run the analysis.${NC}"
        echo -e "${YELLOW}Get it from: https://github.com/settings/tokens (needs read:security_events scope)${NC}"
    else
        echo -e "${RED}No .env or .env.example file found${NC}"
        exit 1
    fi
fi

# Download NLTK data
echo -e "\n${GREEN}Downloading NLTK data...${NC}"
python -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger'); nltk.download('wordnet')"

# Verify installation
echo -e "\n${GREEN}Verifying installation...${NC}"
python -c '
import sys
try:
    import pandas
    import numpy
    import sklearn
    import torch
    import transformers
    import fastapi
    import plotly
    import kaleido
    import aiofiles
    import jinja2
    print("All dependencies verified successfully!")
except ImportError as e:
    print(f"Error: {str(e)}", file=sys.stderr)
    sys.exit(1)
'

if [ $? -ne 0 ]; then
    echo -e "${RED}Critical dependencies are missing. The installation may have failed.${NC}"
    exit 1
fi

echo -e "\n${GREEN}Setup complete!${NC}"

if command -v conda &> /dev/null && [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}To activate this environment in the future, run:${NC}"
    echo -e "${YELLOW}conda activate $ENV_NAME${NC}"
else
    echo -e "${YELLOW}To activate this environment in the future, run:${NC}"
    echo -e "${YELLOW}source venv/bin/activate${NC}"
fi

# Ask user if they want to run the analysis
read -p "Do you want to run the OWASP Top 10 prediction analysis now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "\n${GREEN}Running OWASP Top 10 prediction analysis...${NC}"
    python main.py
else
    echo -e "\n${YELLOW}To run the analysis later:${NC}"
    if command -v conda &> /dev/null && [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}1. conda activate $ENV_NAME${NC}"
    else
        echo -e "${YELLOW}1. source venv/bin/activate${NC}"
    fi
    echo -e "${YELLOW}2. python main.py${NC}"
fi 
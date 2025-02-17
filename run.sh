#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
YELLOW='\033[1;33m'

echo -e "${GREEN}Setting up OWASP Top 10 Predictor...${NC}"

# Check if conda is installed
if ! command -v conda &> /dev/null; then
    echo -e "${RED}Conda is not installed. Please install Miniconda or Anaconda first.${NC}"
    echo -e "${YELLOW}Get it from: https://docs.conda.io/en/latest/miniconda.html${NC}"
    exit 1
fi

# Create and activate conda environment
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

# Upgrade pip to latest version
echo -e "\n${GREEN}Upgrading pip...${NC}"
python -m pip install --upgrade pip

# Install remaining packages with pip
echo -e "\n${GREEN}Installing additional dependencies with pip...${NC}"
if ! python -m pip install \
    "fastapi==0.95.2" \
    "uvicorn==0.22.0" \
    "pydantic==1.10.7" \
    "transformers==4.29.2"; then
    
    echo -e "${RED}Failed to install pip packages${NC}"
    exit 1
fi

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

# Create necessary directories
echo -e "\n${GREEN}Creating necessary directories...${NC}"
mkdir -p results data models logs

# Download NLTK data
echo -e "\n${GREEN}Downloading NLTK data...${NC}"
python -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger'); nltk.download('wordnet')"

# Verify critical dependencies with proper error handling
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
echo -e "${YELLOW}To activate this environment in the future, run:${NC}"
echo -e "${YELLOW}conda activate $ENV_NAME${NC}"

# Ask user if they want to run the analysis
read -p "Do you want to run the analysis now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "\n${GREEN}Running OWASP Top 10 prediction analysis...${NC}"
    if ! python main.py; then
        echo -e "${RED}Analysis failed. Check the logs for more information.${NC}"
        exit 1
    fi
else
    echo -e "\n${YELLOW}To run the analysis later:${NC}"
    echo -e "${YELLOW}1. conda activate $ENV_NAME${NC}"
    echo -e "${YELLOW}2. python main.py${NC}"
fi 
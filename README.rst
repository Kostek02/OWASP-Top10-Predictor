OWASP Top 10 Predictor
=====================

.. image:: https://img.shields.io/badge/python-3.11-blue.svg
   :target: https://www.python.org/downloads/release/python-3110/
.. image:: https://img.shields.io/badge/license-MIT-green.svg
   :target: https://opensource.org/licenses/MIT
.. image:: https://img.shields.io/badge/OWASP-Top%2010-red.svg
   :target: https://owasp.org/www-project-top-ten/

A machine learning-powered tool that predicts future OWASP Top 10 vulnerabilities using historical data, CVE trends, and GitHub security advisories.

Features
--------

- Predicts OWASP Top 10 vulnerabilities for 2025 and 2029
- Analyzes historical vulnerability trends (2013-2021)
- Processes real-time CVE data and GitHub security advisories
- Generates comprehensive prediction reports with visualizations
- Provides confidence scores and trend analysis
- REST API for integration with other tools

Installation
-----------

Using Conda (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    # Clone the repository
    git clone https://github.com/Kostek02/OWASP-Top10-Predictor.git
    cd OWASP-Top10-Predictor

    # Run the setup script
    chmod +x run.sh
    ./run.sh

Manual Installation
~~~~~~~~~~~~~~~~~

.. code-block:: bash

    # Create and activate virtual environment
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\\Scripts\\activate

    # Install dependencies
    pip install -r requirements.txt

Configuration
------------

1. Copy the example environment file:

   .. code-block:: bash

       cp .env.example .env

2. Configure your API keys in `.env`:

   .. code-block:: bash

       GITHUB_TOKEN=your_github_token_here
       NVD_API_KEY=your_nvd_api_key_here

Usage
-----

Command Line
~~~~~~~~~~~

.. code-block:: bash

    # Generate prediction report
    python main.py

    # The report will be generated at: results/prediction_report.md

API Server
~~~~~~~~~

.. code-block:: bash

    # Start the API server
    uvicorn src.api.main:app --reload

    # Access the API documentation at:
    # http://localhost:8000/docs

API Endpoints
~~~~~~~~~~~~

- ``GET /predict/next-top10``: Get predicted OWASP Top 10 vulnerabilities
- ``GET /generate/report``: Generate comprehensive prediction report
- ``GET /data/historical``: Get historical OWASP Top 10 data
- ``GET /health``: Check API health status

Example API Response
~~~~~~~~~~~~~~~~~~

.. code-block:: json

    {
        "predictions": [
            {
                "rank": 1,
                "vulnerability": "Broken Access Control",
                "confidence": 0.396,
                "factors": ["Historical persistence", "Recent CVE trends"]
            }
        ]
    }

Architecture
-----------

Components
~~~~~~~~~~

- **Data Collectors**: Gather data from MITRE, GitHub, and historical OWASP sources
- **Feature Engineering**: Process and transform vulnerability data
- **Prediction Model**: LightGBM-based model with trend analysis
- **Report Generator**: Creates detailed reports with visualizations
- **REST API**: FastAPI-based service for integration

Model Features
~~~~~~~~~~~~~

- Historical vulnerability rankings
- CVE severity trends
- Attack vector analysis
- Ecosystem impact assessment
- Temporal pattern recognition
- Technology trend correlation

Contributing
-----------

1. Fork the repository
2. Create your feature branch: ``git checkout -b feature/new-feature``
3. Commit your changes: ``git commit -am 'Add new feature'``
4. Push to the branch: ``git push origin feature/new-feature``
5. Submit a pull request

License
-------

This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
--------------

- OWASP Foundation for historical Top 10 data
- GitHub Security Advisory Database
- MITRE CVE Database
- Contributors and maintainers

Contact
-------

- Project Link: https://github.com/Kostek02/OWASP-Top10-Predictor
- Report Issues: https://github.com/Kostek02/OWASP-Top10-Predictor/issues 
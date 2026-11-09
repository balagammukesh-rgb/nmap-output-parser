# Nmap Output Parser & Report Generator

A Streamlit web interface for the existing Nmap saved-output parser.

## Run locally

1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the app:

   ```bash
   streamlit run app.py
   ```

5. Open the local URL shown in the terminal (usually http://localhost:8501).

## Deploy to Streamlit Community Cloud

1. Upload `app.py`, `nmap_parser.py`, `requirements.txt`, and `README.md` to a GitHub repository.
2. In Streamlit Community Cloud, create a new app and select that repository.
3. Set the main file path to `app.py`, then deploy.

The app parses saved Nmap output files. It does not execute Nmap scans on the hosting server. Only upload scan results you are authorized to analyze.

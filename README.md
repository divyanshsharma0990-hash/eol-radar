# EOL Radar

End-of-life / end-of-support lookup, part of the VulnPulse suite (VulnPulse, Risk Calc, PatchPilot, EOL Radar).
Public data only (endoflife.date API). No asset or internal data needed.

## Run
    pip install -r requirements.txt
    streamlit run app.py

## Files
- app.py: the app
- requirements.txt: dependencies
- bg.jpeg: copy the SAME background image used in your other apps into this folder (the app falls back to a dark blue gradient if it is missing)

## Deploy
Push the folder to a GitHub repo and deploy on Streamlit Community Cloud with app.py as the main file.

import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from nmap_parser import parse_scan_file

st.set_page_config(page_title="Nmap Report Generator", page_icon="🛡️", layout="wide")

st.title("🛡️ Nmap Output Parser & Report Generator")
st.write("Upload a saved Nmap text output file to view port details, identify watch-list risks, and download a CSV report.")

def parse_uploaded_file(uploaded_file):
    suffix = Path(uploaded_file.name).suffix or ".txt"
    with tempfile.NamedTemporaryFile(mode="wb", suffix=suffix, delete=False) as tmp:
        tmp.write(uploaded_file.getvalue())
        temp_path = Path(tmp.name)
    try:
        return parse_scan_file(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)

def compare_records(old_records, new_records):
    old_map = {(r["protocol"], r["port"]): r for r in old_records}
    new_map = {(r["protocol"], r["port"]): r for r in new_records}
    changes = []
    for key in sorted(set(old_map) | set(new_map)):
        old = old_map.get(key)
        new = new_map.get(key)
        if old is None:
            changes.append({"Change": "ADDED", "Port": f"{key[1]}/{key[0]}", "Details": f'{new["state"]} {new["service"]}'})
        elif new is None:
            changes.append({"Change": "REMOVED", "Port": f"{key[1]}/{key[0]}", "Details": f'{old["state"]} {old["service"]}'})
        elif any(old[field] != new[field] for field in ("state", "service", "version")):
            changes.append({"Change": "CHANGED", "Port": f"{key[1]}/{key[0]}", "Details": f'{old["state"]} → {new["state"]}; {old["service"]} / {new["service"]}'})
    return changes

primary = st.file_uploader("Upload first Nmap scan (.txt)", type=["txt", "nmap", "log"])
comparison = st.file_uploader("Optional: upload a second scan to compare", type=["txt", "nmap", "log"], key="compare")

if primary:
    try:
        records = parse_uploaded_file(primary)
    except Exception as exc:
        st.error(f"Could not read this scan file: {exc}")
        st.stop()

    df = pd.DataFrame(records, columns=["port", "protocol", "state", "service", "version", "risk"])
    open_count = int((df["state"] == "open").sum()) if not df.empty else 0
    closed_count = int((df["state"] == "closed").sum()) if not df.empty else 0
    filtered_count = int((df["state"] == "filtered").sum()) if not df.empty else 0

    st.subheader(f"Scan report: {primary.name}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total ports", len(df))
    c2.metric("Open", open_count)
    c3.metric("Closed", closed_count)
    c4.metric("Filtered", filtered_count)

    st.subheader("Port details")
    if df.empty:
        st.warning("No port rows were recognized. Check that this is a saved Nmap output containing lines such as 22/tcp open ssh.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

    risks = df[df["risk"].fillna("") != ""] if not df.empty else df
    st.subheader("Potential risks")
    if risks.empty:
        st.success("No watch-list matches found in this scan.")
    else:
        st.warning(f"{len(risks)} port row(s) matched the project's risk watch list.")
        st.dataframe(risks, use_container_width=True, hide_index=True)

    csv_bytes = df.to_csv(index=False).encode("utf-8")
    report_name = f"{Path(primary.name).stem}_report.csv"
    st.download_button("⬇️ Download CSV report", data=csv_bytes, file_name=report_name, mime="text/csv")

    if comparison:
        try:
            second_records = parse_uploaded_file(comparison)
            st.subheader("Scan comparison")
            changes = compare_records(records, second_records)
            if changes:
                st.dataframe(pd.DataFrame(changes), use_container_width=True, hide_index=True)
                st.download_button(
                    "⬇️ Download comparison CSV",
                    data=pd.DataFrame(changes).to_csv(index=False).encode("utf-8"),
                    file_name="scan_comparison.csv",
                    mime="text/csv",
                )
            else:
                st.success("No port changes detected between the two scans.")
        except Exception as exc:
            st.error(f"Could not compare the second scan: {exc}")
else:
    st.info("Start by uploading a saved Nmap text output file above.")
    st.caption("This app parses saved scan files. It does not run Nmap scans on the hosting server.")

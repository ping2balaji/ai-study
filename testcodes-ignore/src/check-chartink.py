import datetime
import pandas as pd
import requests
from bs4 import BeautifulSoup as bs

PROCESS_ENDPOINT = "https://chartink.com/screener/process"
SCAN_REFERER = "https://chartink.com/screener/"
SCAN_CLAUSE = "( {33489} ( [0] 15 minute close >= weekly min( 4 , weekly low ) * 1.01 and [0] 15 minute close <= weekly min( 4 , weekly low ) * 1.05 and( {33489} ( ( {33489} ( [0] 15 minute rsi( 7 ) > 88 and [ -1 ] 15 minute rsi( 7 ) <= 88 and [0] 15 minute sma( [0] 15 minute volume , 20 ) > [-1] 15 minute sma( [0] 15 minute volume , 20 ) ) ) or( {33489} ( [-1] 15 minute rsi( 7 ) > 88 and [ -2 ] 15 minute rsi( 7 ) <= 88 and [-1] 15 minute sma( [0] 15 minute volume , 20 ) > [-2] 15 minute sma( [0] 15 minute volume , 20 ) ) ) or( {33489} ( [-2] 15 minute rsi( 7 ) > 88 and [ -3 ] 15 minute rsi( 7 ) <= 88 and [-2] 15 minute sma( [0] 15 minute volume , 20 ) > [-3] 15 minute sma( [0] 15 minute volume , 20 ) ) ) or( {33489} ( [-3] 15 minute rsi( 7 ) > 88 and [ -4 ] 15 minute rsi( 7 ) <= 88 and [-3] 15 minute sma( [0] 15 minute volume , 20 ) > [-4] 15 minute sma( [0] 15 minute volume , 20 ) ) ) or( {33489} ( [-4] 15 minute rsi( 7 ) > 88 and [ -5 ] 15 minute rsi( 7 ) <= 88 and [-4] 15 minute sma( [0] 15 minute volume , 20 ) > [-5] 15 minute sma( [0] 15 minute volume , 20 ) ) ) or( {33489} ( [-5] 15 minute rsi( 7 ) > 88 and [ -6 ] 15 minute rsi( 7 ) <= 88 and [-5] 15 minute sma( [0] 15 minute volume , 20 ) > [-6] 15 minute sma( [0] 15 minute volume , 20 ) ) ) or( {33489} ( [-6] 15 minute rsi( 7 ) > 88 and [ -7 ] 15 minute rsi( 7 ) <= 88 and [-6] 15 minute sma( [0] 15 minute volume , 20 ) > [-7] 15 minute sma( [0] 15 minute volume , 20 ) ) ) ) ) ) )"
# Above scan_clause can be obtained from the above process_endpoint url's payload 
# when you do inspect/dev-tools in network tab from browser in ur chartink page.
# reference: https://medium.com/@akshaybagal/automate-google-spreadsheets-with-chartink-scanner-data-using-python-and-google-sheets-api-81248a45e948

def get_csrf_token(session: requests.Session) -> str:
    """Return CSRF token from screener landing page."""
    response = session.get(SCAN_REFERER, timeout=15)
    response.raise_for_status()
    soup = bs(response.text, "html.parser")
    meta = soup.find("meta", {"name": "csrf-token"})
    if not meta or not meta.get("content"):
        raise RuntimeError("Unable to retrieve CSRF token from Chartink page")
    return meta["content"]


def fetch_scan_payload(session: requests.Session, csrf_token: str) -> dict:
    headers = {
        "Referer": SCAN_REFERER,
        "x-csrf-token": csrf_token,
        "x-requested-with": "XMLHttpRequest",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    }
    payload = {"scan_clause": SCAN_CLAUSE}
    response = session.post(PROCESS_ENDPOINT, headers=headers, data=payload, timeout=30)
    response.raise_for_status()
    try:
        return response.json()
    except ValueError as exc:
        snippet = response.text[:200].strip().replace("\n", " ")
        raise RuntimeError(f"Expected JSON response, got: {snippet}") from exc


def build_dataframe(scan_payload: dict) -> pd.DataFrame:
    rows = scan_payload.get("data", [])
    df = pd.DataFrame(rows)
    df["time_stamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return df


def main() -> None:
    with requests.Session() as session:
        csrf_token = get_csrf_token(session)
        scan_payload = fetch_scan_payload(session, csrf_token)
        df = build_dataframe(scan_payload)
        print(df)


if __name__ == "__main__":
    main()

from __future__ import annotations

"""
fetch_chartink_ohlc.py
----------------------

Supported CLI arguments (use `uv run python fetch_chartink_ohlc.py --help` for defaults):

- `--symbol`            : NSE symbol to fetch (e.g. KPITTECH).
- `--timeframe`         : Chartink timeframe string (e.g. "15 minutes").
- `--scan-link-id`      : Screener scan ID without the `scanlink:` prefix.
- `--indicator-id`      : Indicator layer UUID used in the popup payload.
- `--limit` / `--size`  : Pagination parameters mirrored from Chartink requests.
- `--widget-id`         : Widget identifier (`-1` for default popup fetch).
- `--end-time`          : Epoch ms (or `-1` for latest) used by Chartink.
- `--use-live`          : 1 to request live data, 0 to request cached.
- `--pretty`            : Pretty-print raw JSON and skip chart generation.
- `--chart-dir`         : Destination directory (defaults to `src/charts/`).
- `--chart-type`        : mplfinance chart type (`candle`, `ohlc`, `line`).
- `--chart-style`       : mplfinance style name (`yahoo`, `charles`, etc.).
- `--timezone`          : Pandas timezone name for index conversion (e.g. `Asia/Kolkata`).
- `--fig-ratio`         : Width,height (comma-separated floats) for figure ratio.
- `--fig-scale`         : mplfinance figure scale multiplier.
- `--max-candles`       : Maximum most-recent candles plotted (`-1` keeps all).
- `--no-chart`          : Skip chart rendering even if data fetch succeeds.

example: 
uv run python .\testcodes-ignore\src\fetch_chartink_ohlc.py --symbol KPITTECH --timezone Asia/Kolkata --timeframe "15 minutes"
uv run python .\testcodes-ignore\src\fetch_chartink_ohlc.py --symbol KPITTECH --timezone Asia/Kolkata --timeframe "5 minutes"
"""

import argparse
import datetime
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import numpy as np
import requests
from bs4 import BeautifulSoup

try:
    import pandas as pd
except ImportError:  # pragma: no cover
    pd = None

try:
    import mplfinance as mpf
except ImportError:  # pragma: no cover
    mpf = None

try:
    import matplotlib.pyplot as plt
except ImportError:  # pragma: no cover
    plt = None

SCREENER_URL = "https://chartink.com/screener/"
OAPI_ENDPOINT = "https://chartink.com/oapi"
DEFAULT_SCAN_LINK_ID = "13d002197d466b7ad89c687bf87da755"
DEFAULT_INDICATOR_ID = "c31f5443-d2f4-4cf4-8b4e-92896d64c312"


DEFAULT_CHART_DIR = Path(__file__).resolve().parent / "charts"
DEFAULT_FIG_RATIO = (21.0, 9.0)
DEFAULT_FIG_SCALE = 1.4
DEFAULT_MAX_CANDLES = 900
RSI_PERIOD = 7
RSI_LINES = (40.0, 60.0, 88.0)


def get_csrf_token(session: requests.Session) -> str:
    """Fetch CSRF token and cookies needed for subsequent POST calls."""
    response = session.get(SCREENER_URL, timeout=15)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    meta = soup.find("meta", {"name": "csrf-token"})
    if not meta or not meta.get("content"):
        raise RuntimeError("Unable to locate CSRF token on chartink screener page")
    return meta["content"]


def build_query(symbol: str, scan_link_id: str, indicator_id: str) -> str:
    indicator_field = f"indicatorsetid1layerId{indicator_id}"
    return (
        "select open, high, low, close, volume , Close as "
        f"'{indicator_field}', "
        f"filternumber({{scan-link-scanlink:{scan_link_id}}}) as "
        f"'{indicator_field}-color' "
        f"where symbol='{symbol}'"
    )


def fetch_chart_data(
    session: requests.Session,
    symbol: str,
    timeframe: str,
    scan_link_id: str,
    indicator_id: str,
    limit: int,
    size: int,
    widget_id: int,
    end_time: int,
    use_live: int,
) -> Dict[str, Any]:
    csrf_token = get_csrf_token(session)
    query = build_query(symbol, scan_link_id, indicator_id)
    headers = {
        "Referer": SCREENER_URL,
        "X-CSRF-TOKEN": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    }
    payload = {
        "query": query,
        "use_live": str(use_live),
        "limit": str(limit),
        "size": str(size),
        "widget_id": str(widget_id),
        "end_time": str(end_time),
        "timeframe": timeframe,
        "symbol": symbol,
        "scan_link": f"scanlink:{scan_link_id}",
    }
    response = session.post(
        OAPI_ENDPOINT,
        headers=headers,
        data=payload,
        timeout=30,
    )
    response.raise_for_status()
    try:
        return response.json()
    except ValueError as exc:
        snippet = response.text[:200].strip().replace("\n", " ")
        raise RuntimeError(f"Expected JSON response, got: {snippet}") from exc


def build_dataframe_from_payload(
    payload: Dict[str, Any], tz: str | None = None
) -> "pd.DataFrame":
    """Convert Chartink payload into a pandas DataFrame indexed by timestamp."""
    if pd is None:
        raise RuntimeError(
            "pandas is required to build the OHLC table. "
            "Install it with `uv pip install pandas python-dateutil pytz`."
        )
    meta = payload["metaData"][0]
    trade_times = meta["tradeTimes"]
    column_aliases: Iterable[str] = meta["columnAliases"]
    group = payload["groupData"][0]
    results = group["results"]

    series_map = {
        alias: list(result.values())[0]
        for alias, result in zip(column_aliases, results, strict=False)
    }

    core_columns = ("open", "high", "low", "close", "volume")
    missing = [col for col in core_columns if col not in series_map]
    if missing:
        raise RuntimeError(f"Missing expected columns in payload: {missing}")

    df = pd.DataFrame(
        {col: series_map[col] for col in core_columns},
        index=pd.to_datetime(trade_times, unit="ms"),
    )
    df = df.astype(float, copy=False)

    if tz:
        df.index = df.index.tz_localize("UTC").tz_convert(tz).tz_localize(None)

    return df


def _compute_rsi(close: "pd.Series", period: int = RSI_PERIOD) -> "pd.Series":
    if pd is None or len(close) < period + 1:
        return pd.Series(np.nan, index=close.index)

    delta = close.diff().fillna(0)
    gains = delta.where(delta > 0, 0.0)
    losses = (-delta).where(delta < 0, 0.0)

    gain_vals = gains.to_numpy(dtype=float)
    loss_vals = losses.to_numpy(dtype=float)
    rsi_vals = np.full_like(gain_vals, np.nan, dtype=float)

    avg_gain = gain_vals[1 : period + 1].mean()
    avg_loss = loss_vals[1 : period + 1].mean()

    if avg_loss == 0:
        rsi_vals[period] = 100.0
    else:
        rs = avg_gain / avg_loss
        rsi_vals[period] = 100 - (100 / (1 + rs))

    for idx in range(period + 1, len(gain_vals)):
        avg_gain = ((avg_gain * (period - 1)) + gain_vals[idx]) / period
        avg_loss = ((avg_loss * (period - 1)) + loss_vals[idx]) / period

        if avg_loss == 0:
            rsi_vals[idx] = 100.0
        else:
            rs = avg_gain / avg_loss
            rsi_vals[idx] = 100 - (100 / (1 + rs))

    return pd.Series(rsi_vals, index=close.index)


def save_chart_image(
    df: pd.DataFrame,
    symbol: str,
    timeframe: str,
    chart_dir: Path,
    chart_type: str,
    chart_style: str,
    fig_ratio: Tuple[float, float],
    fig_scale: float,
    max_candles: int,
) -> Path:
    if mpf is None:
        raise RuntimeError(
            "mplfinance is required to export charts. "
            "Install it with `uv pip install mplfinance`."
        )

    if df.empty:
        raise RuntimeError("No rows available to render chart.")

    if max_candles > 0:
        working_df = df.iloc[-max_candles:].copy()
    else:
        working_df = df.copy()

    output_dir = chart_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    current_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    timeframe_slug = timeframe.replace(" ", "")
    filename = f"{symbol}_{timeframe_slug}_{current_ts}.png"
    output_path = output_dir / filename

    add_plots = []
    if pd is None:
        raise RuntimeError(
            "pandas is required to build the OHLC table. "
            "Install it with `uv pip install pandas python-dateutil pytz`."
        )
    if plt is None:
        raise RuntimeError(
            "matplotlib is required to export charts. "
            "Install it with `uv pip install matplotlib`."
        )

    rsi_series = _compute_rsi(working_df["close"])
    if not rsi_series.dropna().empty:
        add_plots.append(
            mpf.make_addplot(
                rsi_series,
                panel=2,
                color="tab:purple",
                ylabel=f"RSI({RSI_PERIOD})",
            )
        )
        line_colors = ("tab:olive", "tab:orange", "tab:red")
        for level, color in zip(RSI_LINES, line_colors):
            add_plots.append(
                mpf.make_addplot(
                    pd.Series(level, index=working_df.index),
                    panel=2,
                    color=color,
                    linestyle="--",
                )
            )

    panel_ratios = (8, 2, 2) if add_plots else (8, 2)

    try:
        base_style = mpf.make_mpf_style(
            base_mpf_style=chart_style,
            gridaxis="horizontal",
            gridstyle=":",
            gridcolor="#dddddd",
            facecolor="white",
            edgecolor="#f5f5f5",
        )
    except ValueError:
        base_style = mpf.make_mpf_style(
            gridaxis="horizontal",
            gridstyle=":",
            gridcolor="#dddddd",
            facecolor="white",
            edgecolor="#f5f5f5",
        )

    fig, axes = mpf.plot(
        working_df,
        type=chart_type,
        volume=True,
        style=base_style,
        figratio=fig_ratio,
        figscale=fig_scale,
        addplot=add_plots if add_plots else None,
        panel_ratios=panel_ratios,
        warn_too_much_data=max(working_df.shape[0] + 100, 1200),
        returnfig=True,
    )

    axes = list(np.atleast_1d(axes))
    price_ax = axes[0]
    price_ax.text(
        0.01,
        0.99,
        f"{symbol} · {timeframe}",
        transform=price_ax.transAxes,
        ha="left",
        va="top",
        fontsize=12,
        fontweight="bold",
        bbox=dict(facecolor="white", alpha=0.6, edgecolor="none", pad=4),
    )

    for ax in axes:
        ax.grid(False)
        ax.set_facecolor("white")
        ax.yaxis.grid(True, linestyle=":", alpha=0.2)

    if add_plots:
        rsi_ax = axes[-1]
        rsi_ax.set_ylim(0, 100)
        rsi_ax.set_yticks([0, 20, 40, 60, 80, 100])
        rsi_ax.yaxis.grid(True, linestyle=":", alpha=0.2)
    if len(axes) > 1:
        axes[1].yaxis.grid(False)

    if axes:
        tick_count = max(2, len(working_df) // 75)
        step = max(1, len(working_df) // tick_count)
        tick_indices = list(range(0, len(working_df), step))
        tick_labels = [
            working_df.index[i].strftime("%Y-%m-%d %H:%M") for i in tick_indices
        ]

        for ax in axes[:-1]:
            ax.tick_params(labelbottom=False)

        axes[-1].set_xticks(tick_indices, tick_labels, rotation=45, ha="right")
        axes[-1].tick_params(labelsize=9, axis="x", which="major")

    fig.savefig(str(output_path), dpi=150, bbox_inches="tight")
    plt.close(fig)
    return output_path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch OHLC + indicator series from Chartink screener popup."
    )
    parser.add_argument("--symbol", default="KPITTECH", help="NSE symbol to query")
    parser.add_argument(
        "--timeframe",
        default="15 minutes",
        help="Timeframe string as used by Chartink (e.g. '15 minutes')",
    )
    parser.add_argument(
        "--scan-link-id",
        default=DEFAULT_SCAN_LINK_ID,
        help="Scan link identifier without the 'scanlink:' prefix",
    )
    parser.add_argument(
        "--indicator-id",
        default=DEFAULT_INDICATOR_ID,
        help="Indicator layer identifier from Chartink",
    )
    parser.add_argument("--limit", type=int, default=1, help="Rows per query limit")
    parser.add_argument("--size", type=int, default=1367, help="Series size to request")
    parser.add_argument(
        "--widget-id",
        type=int,
        default=-1,
        help="Widget id sent by Chartink javascript (-1 by default)",
    )
    parser.add_argument(
        "--end-time",
        type=int,
        default=-1,
        help="End time parameter passed to Chartink (use -1 for latest)",
    )
    parser.add_argument(
        "--use-live",
        type=int,
        default=1,
        choices=(0, 1),
        help="Whether to request live data (1) or cached data (0)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the resulting JSON payload",
    )
    parser.add_argument(
        "--chart-dir",
        default=None,
        help=(
            "Directory (relative to src/ by default) to save the mplfinance chart. "
            "Defaults to src/charts when omitted."
        ),
    )
    parser.add_argument(
        "--chart-type",
        default="candle",
        choices=("candle", "ohlc", "line"),
        help="Chart type to render with mplfinance",
    )
    parser.add_argument(
        "--chart-style",
        default="yahoo",
        help="mplfinance style name to apply (e.g. 'yahoo', 'charles', 'nightclouds')",
    )
    parser.add_argument(
        "--timezone",
        default=None,
        help="Timezone name (e.g. 'Asia/Kolkata') for the chart index; defaults to UTC",
    )
    parser.add_argument(
        "--fig-ratio",
        default="21,9",
        help="Figure aspect ratio as 'width,height' (floats). Default widens the chart.",
    )
    parser.add_argument(
        "--fig-scale",
        type=float,
        default=DEFAULT_FIG_SCALE,
        help="Scale multiplier applied to the base figure size (default widens chart).",
    )
    parser.add_argument(
        "--max-candles",
        type=int,
        default=DEFAULT_MAX_CANDLES,
        help=(
            "Maximum number of most recent candles to plot (default 900). "
            "Use -1 to include the full dataset."
        ),
    )
    parser.add_argument(
        "--no-chart",
        action="store_true",
        help="Skip chart generation even if dependencies are available.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    with requests.Session() as session:
        payload = fetch_chart_data(
            session=session,
            symbol=args.symbol,
            timeframe=args.timeframe,
            scan_link_id=args.scan_link_id,
            indicator_id=args.indicator_id,
            limit=args.limit,
            size=args.size,
            widget_id=args.widget_id,
            end_time=args.end_time,
            use_live=args.use_live,
        )
    if args.pretty:
        print(json.dumps(payload, indent=2))

    if args.no_chart:
        return

    if args.chart_dir:
        raw_dir = Path(args.chart_dir)
        chart_dir = (
            raw_dir if raw_dir.is_absolute() else DEFAULT_CHART_DIR.parent / raw_dir
        )
    else:
        chart_dir = DEFAULT_CHART_DIR

    df = build_dataframe_from_payload(payload, tz=args.timezone)

    try:
        fig_ratio = tuple(float(x) for x in args.fig_ratio.split(","))
        if len(fig_ratio) != 2:
            raise ValueError
    except ValueError as exc:  # pragma: no cover
        raise RuntimeError("Invalid --fig-ratio value. Expecting 'width,height'.") from exc

    output_path = save_chart_image(
        df=df,
        symbol=args.symbol,
        timeframe=args.timeframe,
        chart_dir=chart_dir,
        chart_type=args.chart_type,
        chart_style=args.chart_style,
        fig_ratio=fig_ratio or DEFAULT_FIG_RATIO,
        fig_scale=args.fig_scale,
        max_candles=args.max_candles,
    )
    print(f"Saved mplfinance chart to {output_path}")


if __name__ == "__main__":
    main()

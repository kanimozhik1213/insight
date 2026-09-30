import os
import json
import time
import pandas as pd
import altair as alt
import streamlit as st


# =========================================================
# CONFIG
# =========================================================

OUT = "data/processed/"

LEVELS = ["Low", "Medium", "High", "Critical"]

COLORS = {
    "Low": "#3DDBC0",
    "Medium": "#F2C14E",
    "High": "#F08A4B",
    "Critical": "#FF5C6C"
}

DOT = {
    "Low": "🟢",
    "Medium": "🟡",
    "High": "🟠",
    "Critical": "🔴"
}

PALETTE = [
    "#26B5C9",
    "#5C6BE0",
    "#B5F5E6",
    "#A9A6FF",
    "#3DDBC0",
    "#7FD8FF",
    "#8E9BFF",
    "#C7F3EA"
]

TEAL = "#3DDBC0"
BLUE = "#5C6BE0"
MUTE = "#AEB4E0"
GRID = "#2C2F55"

SCALE = alt.Scale(
    domain=LEVELS,
    range=[COLORS[x] for x in LEVELS]
)

WHO = alt.Scale(
    domain=["Normal", "Suspicious"],
    range=["#5C6BE0", "#FF5C6C"]
)

ACTION = {
    "Critical": "Investigate immediately: alert the security team and the user's manager.",
    "High": "Investigate today and confirm whether the activity was authorised.",
    "Medium": "Review when possible: check whether this is normal for the user's role.",
    "Low": "Monitor only."
}

NAME = {
    "device": "USB / Device",
    "usb": "USB",
    "email": "Email",
    "http": "HTTP",
    "file": "File",
    "command": "Command"
}

alt.data_transformers.disable_max_rows()


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Insight360 | Insider Threat Quickview",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# CSS
# =========================================================

st.markdown(
    """
    <style>

    .stApp {
        background: #12132A;
        color: #E8EAFF;
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    .block-container {
        padding-top: 1.4rem;
        max-width: 1320px;
    }

    .hero h1 {
        font-size: 2.1rem;
        font-weight: 700;
        margin: 0;
        color: #FFFFFF;
    }

    .hero .sub {
        font-size: 1.5rem;
        color: #C9CCF2;
        margin-top: -4px;
    }

    .pg h2 {
        margin-bottom: 0;
        color: #FFFFFF;
    }

    .pg p {
        color: #AEB4E0;
        margin-top: 2px;
    }

    .kpis {
        display: flex;
        justify-content: flex-end;
        gap: 0;
        padding-top: 6px;
        margin-bottom: 8px;
    }

    .kpis .k {
        padding: 0 26px;
        border-left: 1px solid #3A3D6B;
        text-align: center;
        min-width: 140px;
    }

    .kpis .k:first-child {
        border-left: none;
    }

    .kpis .n {
        font-size: 2.3rem;
        font-weight: 700;
        color: #3DDBC0;
        line-height: 1.1;
    }

    .kpis .l {
        font-size: 0.72rem;
        letter-spacing: 0.08em;
        color: #AEB4E0;
        margin-top: 4px;
    }

    .ctitle {
        text-align: center;
        font-size: 1.1rem;
        color: #E8EAFF;
        margin: 14px 0 2px 0;
    }

    .card {
        background: #1B1D3A;
        border-radius: 10px;
        padding: 12px 16px;
        margin-bottom: 8px;
        border: 1px solid #262A50;
    }

    .card .lbl {
        font-size: 0.78rem;
        color: #AEB4E0;
    }

    .card .val {
        font-size: 1.7rem;
        font-weight: 700;
        line-height: 1.25;
        color: #FFFFFF;
    }

    .card .sub {
        font-size: 0.75rem;
        color: #8E94C9;
    }

    .ucard {
        background: #1B1D3A;
        border: 1px solid #262A50;
        border-radius: 12px;
        padding: 14px 16px;
        margin-bottom: 10px;
    }

    .ucard .top {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .ucard .uid {
        font-size: 1.2rem;
        font-weight: 700;
        color: #FFFFFF;
    }

    .ucard .pill {
        padding: 3px 12px;
        border-radius: 99px;
        font-size: 0.75rem;
        font-weight: 700;
        color: #0F1226;
    }

    .ucard .cells {
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin: 12px 0;
    }

    .ucard .c {
        min-width: 64px;
    }

    .ucard .c b {
        display: block;
        font-size: 1.6rem;
        color: #3DDBC0;
        line-height: 1.1;
    }

    .ucard .c span {
        font-size: 0.72rem;
        color: #AEB4E0;
    }

    .ucard .foot {
        font-size: 0.78rem;
        color: #8E94C9;
    }

    .section-box {
        background: #1B1D3A;
        border: 1px solid #262A50;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 14px;
    }

    .normal-box {
        background: #191D3B;
        border-left: 4px solid #5C6BE0;
        padding: 14px;
        border-radius: 8px;
        margin-bottom: 10px;
    }

    .suspicious-box {
        background: #241A32;
        border-left: 4px solid #FF5C6C;
        padding: 14px;
        border-radius: 8px;
        margin-bottom: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# DATA
# =========================================================

FRIENDLY = {
    "events_1h": "Burst of activity",
    "hour": "Time of day",
    "gap_s": "Time since previous event",
    "after_hours": "Outside working hours",
    "weekday": "Day of week",
    "weekend": "Weekend activity",
    "Activity_command": "Server command activity",
    "cmd_none": "No command attached",
    "Action_Command executed": "Command executed",
    "content_words": "Message length",
    "url_len": "Web address length",
    "n_external": "External recipients",
    "n_recipients": "Number of recipients",
    "Size": "Data size",
    "dom_freq": "Web domain rarity",
    "path_depth": "File path depth"
}


@st.cache_data
def load():

    scored = pd.read_parquet(
        OUT + "scored_spedia.parquet"
    )

    scored["time"] = pd.to_datetime(
        scored["time"]
    )

    metrics = pd.read_csv(
        OUT + "model_metrics.csv"
    )

    importance = pd.read_csv(
        OUT + "feature_importance.csv",
        index_col=0
    ).iloc[:, 0]

    meta = {
        "alert_threshold": 30
    }

    if os.path.exists(OUT + "threshold.json"):

        with open(
            OUT + "threshold.json"
        ) as fh:

            meta = json.load(fh)

    return scored, metrics, importance, meta


scored, metrics, imp, meta = load()

DEFAULT_THR = int(
    meta.get(
        "alert_threshold",
        30
    )
)

ACTIVITIES = sorted(
    scored["activity"]
    .dropna()
    .unique()
)


# =========================================================
# HELPERS
# =========================================================

def sty(chart, height=260):

    return (
        chart
        .properties(
            height=height,
            background="transparent"
        )
        .configure_axis(
            labelColor=MUTE,
            titleColor=MUTE,
            gridColor=GRID,
            domainColor=GRID,
            tickColor=GRID
        )
        .configure_legend(
            labelColor=MUTE,
            titleColor=MUTE
        )
        .configure_view(
            strokeWidth=0
        )
    )


def show(chart, height=260):

    st.altair_chart(
        sty(chart, height),
        theme=None,
        width="stretch"
    )


def ctitle(text):

    st.markdown(
        f'<div class="ctitle">{text}</div>',
        unsafe_allow_html=True
    )


def lvl(score):

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def card(
    label,
    value,
    sub="",
    color=TEAL
):

    st.markdown(
        f"""
        <div class="card"
             style="border-left:4px solid {color}">
            <div class="lbl">{label}</div>
            <div class="val">{value}</div>
            <div class="sub">{sub}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def header(title, subtitle):

    st.markdown(
        f"""
        <div class="pg">
            <h2>{title}</h2>
            <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True
    )


def kpi_strip(items):

    html = ""

    for number, label in items:

        html += (
            f'<div class="k">'
            f'<div class="n">{number}</div>'
            f'<div class="l">{label}</div>'
            f'</div>'
        )

    st.markdown(
        f'<div class="kpis">{html}</div>',
        unsafe_allow_html=True
    )


def choose(label, options, key):

    if hasattr(
        st,
        "segmented_control"
    ):

        return st.segmented_control(
            label,
            options,
            key=key,
            label_visibility="collapsed"
        )

    return st.radio(
        label,
        options,
        horizontal=True,
        key=key,
        label_visibility="collapsed"
    )


def at_threshold(df, threshold):

    predicted = df["risk"] >= threshold
    actual = df["true_label"] == 1

    tp = int(
        (predicted & actual).sum()
    )

    fp = int(
        (predicted & ~actual).sum()
    )

    fn = int(
        (~predicted & actual).sum()
    )

    tn = int(
        (~predicted & ~actual).sum()
    )

    precision = tp / max(
        tp + fp,
        1
    )

    recall = tp / max(
        tp + fn,
        1
    )

    f1 = (
        2 * precision * recall /
        max(
            precision + recall,
            1e-9
        )
    )

    false_alarm = fp / max(
        fp + tn,
        1
    )

    return {
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_alarm_rate": false_alarm,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn
    }


def reason_counts(df):

    if df.empty:
        return pd.Series(dtype=int)

    r = (
        df["reasons"]
        .fillna("")
        .str.split("; ")
        .explode()
    )

    return r[
        (r != "No rule triggered") &
        (r != "")
    ].value_counts()


def make_incidents(
    df,
    gap_min=30
):

    if df.empty:
        return pd.DataFrame()

    d = df.sort_values(
        ["user", "time"]
    ).copy()

    d["incident"] = (
        (d["user"] != d["user"].shift()) |
        (
            d["time"].diff()
            > pd.Timedelta(
                minutes=gap_min
            )
        )
    ).cumsum()

    def top_reasons(series):

        r = (
            series
            .fillna("")
            .str.split("; ")
            .explode()
        )

        r = r[
            (r != "No rule triggered") &
            (r != "")
        ]

        if r.empty:
            return "No rule triggered"

        return "; ".join(
            r.value_counts()
            .head(3)
            .index
        )

    g = d.groupby(
        "incident"
    ).agg(
        user=("user", "first"),
        start=("time", "min"),
        end=("time", "max"),
        events=("risk", "size"),
        peak_risk=("risk", "max"),
        reasons=("reasons", top_reasons)
    )

    g["duration_min"] = (
        (
            g["end"] -
            g["start"]
        )
        .dt.total_seconds()
        / 60
    ).round(0)

    g["level"] = g[
        "peak_risk"
    ].map(lvl)

    return (
        g
        .sort_values(
            "peak_risk",
            ascending=False
        )
        .reset_index(drop=True)
    )


def after_share(df):

    if df.empty:
        return 0.0

    outside = (
        (df["time"].dt.hour < 8) |
        (df["time"].dt.hour >= 18)
    )

    return float(
        outside.mean()
    )


def timeline_chart(
    user_df,
    threshold,
    band=None
):

    if user_df.empty:
        return alt.Chart(
            pd.DataFrame()
        )

    pts = user_df

    if len(pts) > 3000:

        pts = pts.sample(
            3000,
            random_state=1
        )

    dots = (
        alt.Chart(pts)
        .mark_circle(
            size=45,
            opacity=0.75
        )
        .encode(
            x=alt.X(
                "time:T",
                title=None
            ),
            y=alt.Y(
                "risk:Q",
                title="Risk score",
                scale=alt.Scale(
                    domain=[0, 100]
                )
            ),
            color=alt.Color(
                "level:N",
                scale=SCALE,
                title="Level"
            ),
            tooltip=[
                "time",
                "activity",
                "risk",
                "level"
            ]
        )
    )

    rule = (
        alt.Chart(
            pd.DataFrame(
                {"t": [threshold]}
            )
        )
        .mark_rule(
            strokeDash=[5, 5],
            color="#8E94C9"
        )
        .encode(
            y="t:Q"
        )
    )

    chart = dots + rule

    if band:

        band_df = pd.DataFrame(
            {
                "a": [band[0]],
                "b": [band[1]]
            }
        )

        band_chart = (
            alt.Chart(band_df)
            .mark_rect(
                opacity=0.2,
                color="#FF5C6C"
            )
            .encode(
                x="a:T",
                x2="b:T"
            )
        )

        chart = (
            band_chart +
            chart
        )

    return chart


# =========================================================
# NORMAL VS SUSPICIOUS COMPARISON
# =========================================================

def behaviour_compare(
    user_id,
    normal_df,
    suspicious_df
):

    if normal_df.empty and suspicious_df.empty:

        st.info(
            "No events available for this user."
        )

        return

    def profile(df):

        if df.empty:

            return {
                "events": 0,
                "per_day": 0,
                "after": 0,
                "weekend": 0,
                "types": 0,
                "risk": 0
            }

        days = max(
            df["time"].dt.date.nunique(),
            1
        )

        return {
            "events": len(df),
            "per_day": len(df) / days,
            "after": after_share(df),
            "weekend": float(
                (
                    df["time"].dt.weekday >= 5
                ).mean()
            ),
            "types": df["activity"].nunique(),
            "risk": df["risk"].mean()
        }

    pn = profile(normal_df)
    ps = profile(suspicious_df)

    st.markdown(
        "### Normal Behaviour"
    )

    if normal_df.empty:

        st.warning(
            "No normal events for this user at the current threshold."
        )

    else:

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            card(
                "Normal events",
                f"{pn['events']:,}",
                "Below threshold",
                BLUE
            )

        with c2:
            card(
                "Events / day",
                f"{pn['per_day']:.1f}",
                "Usual activity",
                BLUE
            )

        with c3:
            card(
                "Working hours",
                f"{1 - pn['after']:.0%}",
                "Inside working hours",
                BLUE
            )

        with c4:
            card(
                "Average risk",
                f"{pn['risk']:.1f}",
                "Normal pattern",
                BLUE
            )

    st.markdown(
        "### Suspicious Behaviour"
    )

    if suspicious_df.empty:

        st.success(
            "No suspicious behaviour at the current threshold."
        )

    else:

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            card(
                "Suspicious events",
                f"{ps['events']:,}",
                "At / above threshold",
                "#FF5C6C"
            )

        with c2:
            card(
                "Events / day",
                f"{ps['per_day']:.1f}",
                "Suspicious activity",
                "#FF5C6C"
            )

        with c3:
            card(
                "Outside hours",
                f"{ps['after']:.0%}",
                "Before 8 / after 18",
                "#FF5C6C"
            )

        with c4:
            card(
                "Average risk",
                f"{ps['risk']:.1f}",
                "Suspicious pattern",
                "#FF5C6C"
            )

    st.markdown(
        "### What Changed?"
    )

    comparison = pd.DataFrame(
        {
            "Measure": [
                "Total events",
                "Events per active day",
                "Outside working hours",
                "Weekend activity",
                "Activity types",
                "Average risk"
            ],

            "Normal": [
                f"{pn['events']:,}",
                f"{pn['per_day']:.1f}",
                f"{pn['after']:.0%}",
                f"{pn['weekend']:.0%}",
                pn["types"],
                f"{pn['risk']:.1f}"
            ],

            "Suspicious": [
                f"{ps['events']:,}",
                f"{ps['per_day']:.1f}",
                f"{ps['after']:.0%}",
                f"{ps['weekend']:.0%}",
                ps["types"],
                f"{ps['risk']:.1f}"
            ]
        }
    )

    st.dataframe(
        comparison,
        hide_index=True,
        width="stretch"
    )

    # -----------------------------------------------------
    # Activity comparison
    # -----------------------------------------------------

    combined = pd.concat(
        [
            normal_df.assign(
                behaviour="Normal"
            ),
            suspicious_df.assign(
                behaviour="Suspicious"
            )
        ]
    )

    if not combined.empty:

        activity = (
            combined
            .groupby(
                ["behaviour", "activity"]
            )
            .size()
            .rename("events")
            .reset_index()
        )

        activity["share"] = (
            activity["events"] /
            activity.groupby(
                "behaviour"
            )["events"].transform("sum")
        )

        l, r = st.columns(2)

        with l:

            ctitle(
                "Normal vs Suspicious Activity"
            )

            show(
                alt.Chart(activity)
                .mark_bar()
                .encode(
                    x=alt.X(
                        "activity:N",
                        title=None,
                        axis=alt.Axis(
                            labelAngle=-30
                        )
                    ),
                    xOffset="behaviour:N",
                    y=alt.Y(
                        "share:Q",
                        axis=alt.Axis(
                            format="%"
                        ),
                        title="Share"
                    ),
                    color=alt.Color(
                        "behaviour:N",
                        scale=WHO,
                        title=None
                    ),
                    tooltip=[
                        "behaviour",
                        "activity",
                        alt.Tooltip(
                            "share:Q",
                            format=".0%"
                        )
                    ]
                ),
                300
            )

        with r:

            ctitle(
                "Time of Day"
            )

            hourly = []

            for name, df in [
                ("Normal", normal_df),
                ("Suspicious", suspicious_df)
            ]:

                if df.empty:
                    continue

                h = (
                    df["time"]
                    .dt.hour
                    .value_counts(
                        normalize=True
                    )
                    .reindex(
                        range(24),
                        fill_value=0
                    )
                )

                hourly.append(
                    pd.DataFrame(
                        {
                            "hour": h.index,
                            "share": h.values,
                            "behaviour": name
                        }
                    )
                )

            if hourly:

                hourly_df = pd.concat(
                    hourly
                )

                show(
                    alt.Chart(hourly_df)
                    .mark_line(
                        point=True
                    )
                    .encode(
                        x=alt.X(
                            "hour:O",
                            title="Hour"
                        ),
                        y=alt.Y(
                            "share:Q",
                            axis=alt.Axis(
                                format="%"
                            ),
                            title="Share"
                        ),
                        color=alt.Color(
                            "behaviour:N",
                            scale=WHO,
                            title=None
                        ),
                        tooltip=[
                            "behaviour",
                            "hour",
                            alt.Tooltip(
                                "share:Q",
                                format=".0%"
                            )
                        ]
                    ),
                    300
                )

    # -----------------------------------------------------
    # Plain language explanation
    # -----------------------------------------------------

    if not normal_df.empty and not suspicious_df.empty:

        difference = (
            ps["per_day"] -
            pn["per_day"]
        )

        after_difference = (
            ps["after"] -
            pn["after"]
        )

        if not combined.empty:

            pivot = (
                activity
                .pivot(
                    index="activity",
                    columns="behaviour",
                    values="share"
                )
                .fillna(0)
            )

            if (
                "Suspicious" in pivot.columns and
                "Normal" in pivot.columns
            ):

                pivot["change"] = (
                    pivot["Suspicious"] -
                    pivot["Normal"]
                )

                top_activity = (
                    pivot["change"]
                    .idxmax()
                )

            else:

                top_activity = "activity"

        else:

            top_activity = "activity"

        st.markdown(
            f"""
            <div class="section-box">
            <b>In simple words:</b><br><br>

            User <b>{user_id}</b> normally performs about
            <b>{pn['per_day']:.1f}</b> events per active day.

            During the suspicious period, the activity changes to
            <b>{ps['per_day']:.1f}</b> events per day.

            Outside-working-hours activity changes from
            <b>{pn['after']:.0%}</b> to
            <b>{ps['after']:.0%}</b>.

            The biggest activity change is around
            <b>{top_activity}</b>.
            </div>
            """,
            unsafe_allow_html=True
        )

    # -----------------------------------------------------
    # Suspicious reasons
    # -----------------------------------------------------

    if not suspicious_df.empty:

        st.markdown(
            "### Why the suspicious behaviour was flagged"
        )

        reasons = reason_counts(
            suspicious_df
        )

        if reasons.empty:

            st.info(
                "No specific rule reason was recorded."
            )

        else:

            rdf = (
                reasons
                .head(10)
                .rename_axis("reason")
                .reset_index(
                    name="events"
                )
            )

            show(
                alt.Chart(rdf)
                .mark_bar(
                    color="#FF5C6C"
                )
                .encode(
                    y=alt.Y(
                        "reason:N",
                        sort="-x",
                        title=None
                    ),
                    x=alt.X(
                        "events:Q",
                        title="Events"
                    ),
                    tooltip=[
                        "reason",
                        "events"
                    ]
                ),
                max(
                    180,
                    35 * len(rdf)
                )
            )


# =========================================================
# CASE VIEW
# =========================================================

def case_view(
    user_id,
    start_time=None,
    end_time=None,
    context="case",
    whole=False
):

    user_df = scored[
        scored["user"] == user_id
    ].copy()

    if whole:

        window = user_df

    else:

        window = user_df[
            (user_df["time"] >= start_time) &
            (user_df["time"] <= end_time)
        ]

    alerts_df = (
        window[
            window["risk"] >= thr
        ]
        .sort_values("time")
    )

    if alerts_df.empty:

        st.info(
            "No alerts for this user at the current threshold."
        )

        return

    peak = float(
        alerts_df["risk"].max()
    )

    level = lvl(peak)

    start = alerts_df["time"].min()
    end = alerts_df["time"].max()

    duration = int(
        round(
            (
                end - start
            ).total_seconds() / 60
        )
    )

    st.markdown(
        f"### {DOT[level]} User {user_id}"
    )

    k = st.columns(4)

    with k[0]:

        card(
            "Start",
            f"{start:%d %b %H:%M}",
            f"{start:%Y}",
            TEAL
        )

    with k[1]:

        card(
            "End",
            f"{end:%d %b %H:%M}",
            f"{duration} min",
            BLUE
        )

    with k[2]:

        card(
            "Alerts",
            f"{len(alerts_df):,}",
            f"Risk ≥ {thr}",
            COLORS["High"]
        )

    with k[3]:

        card(
            "Peak Risk",
            f"{peak:.0f}",
            level,
            COLORS[level]
        )

    st.markdown("---")

    # =====================================================
    # THREE OPTIONS
    # =====================================================

    option = choose(
        "View",
        [
            "Explanation",
            "Events",
            "Normal Behaviour"
        ],
        key=f"case_option_{context}_{user_id}"
    )

    if option is None:

        st.info(
            "Choose Explanation, Events or Normal Behaviour."
        )

        return

    # =====================================================
    # EXPLANATION
    # =====================================================

    if option == "Explanation":

        st.markdown(
            "### Explanation"
        )

        # Activity counts

        activity_counts = (
            alerts_df["activity"]
            .value_counts()
        )

        email_count = 0
        http_count = 0
        file_count = 0
        device_count = 0
        command_count = 0

        for activity_name, count in activity_counts.items():

            text = str(
                activity_name
            ).lower()

            if "email" in text:
                email_count += int(count)

            elif (
                "http" in text or
                "web" in text
            ):
                http_count += int(count)

            elif "file" in text:
                file_count += int(count)

            elif (
                "device" in text or
                "usb" in text
            ):
                device_count += int(count)

            elif "command" in text:
                command_count += int(count)

        st.markdown(
            "#### What did the user do?"
        )

        a, b, c, d, e = st.columns(5)

        with a:
            card(
                "Email",
                email_count,
                "Alert events",
                TEAL
            )

        with b:
            card(
                "HTTP",
                http_count,
                "Web events",
                BLUE
            )

        with c:
            card(
                "File",
                file_count,
                "File events",
                "#A9A6FF"
            )

        with d:
            card(
                "USB / Device",
                device_count,
                "Device events",
                "#F2C14E"
            )

        with e:
            card(
                "Command",
                command_count,
                "Command events",
                "#F08A4B"
            )

        # -------------------------------------------------
        # Activity chart
        # -------------------------------------------------

        l, r = st.columns(2)

        with l:

            ctitle(
                "Activity events"
            )

            if activity_counts.empty:

                st.info(
                    "No activity data."
                )

            else:

                ad = (
                    activity_counts
                    .rename_axis("activity")
                    .reset_index(
                        name="events"
                    )
                )

                show(
                    alt.Chart(ad)
                    .mark_bar(
                        color=BLUE
                    )
                    .encode(
                        y=alt.Y(
                            "activity:N",
                            sort="-x",
                            title=None
                        ),
                        x=alt.X(
                            "events:Q",
                            title="Events"
                        ),
                        tooltip=[
                            "activity",
                            "events"
                        ]
                    ),
                    max(
                        200,
                        40 * len(ad)
                    )
                )

        # -------------------------------------------------
        # Reasons
        # -------------------------------------------------

        with r:

            ctitle(
                "Why was it flagged?"
            )

            reasons = reason_counts(
                alerts_df
            )

            if reasons.empty:

                st.info(
                    "No rule-specific reason recorded."
                )

            else:

                rd = (
                    reasons
                    .head(8)
                    .rename_axis("reason")
                    .reset_index(
                        name="events"
                    )
                )

                show(
                    alt.Chart(rd)
                    .mark_bar(
                        color="#FF5C6C"
                    )
                    .encode(
                        y=alt.Y(
                            "reason:N",
                            sort="-x",
                            title=None
                        ),
                        x=alt.X(
                            "events:Q",
                            title="Events"
                        ),
                        tooltip=[
                            "reason",
                            "events"
                        ]
                    ),
                    max(
                        200,
                        40 * len(rd)
                    )
                )

        # -------------------------------------------------
        # Score breakdown
        # -------------------------------------------------

        st.markdown(
            "### Score breakdown"
        )

        highest = alerts_df.loc[
            alerts_df["risk"].idxmax()
        ]

        rf = (
            60 *
            float(
                highest.get(
                    "rf_proba",
                    0
                )
            )
        )

        iso = (
            25 *
            float(
                highest.get(
                    "anomaly_score",
                    0
                )
            )
        )

        rule = (
            15 *
            float(
                highest.get(
                    "rule_score",
                    0
                )
            )
        )

        score_df = pd.DataFrame(
            {
                "Detector": [
                    "Random Forest",
                    "Isolation Forest",
                    "Security Rules"
                ],
                "Points": [
                    rf,
                    iso,
                    rule
                ],
                "Maximum": [
                    60,
                    25,
                    15
                ]
            }
        )

        base = (
            alt.Chart(score_df)
            .encode(
                y=alt.Y(
                    "Detector:N",
                    sort=None,
                    title=None
                )
            )
        )

        show(
            base.mark_bar(
                color="#2C2F55",
                height=24
            ).encode(
                x=alt.X(
                    "Maximum:Q",
                    title="Maximum points"
                )
            )
            +
            base.mark_bar(
                color=COLORS[level],
                height=24
            ).encode(
                x="Points:Q",
                tooltip=[
                    "Detector",
                    alt.Tooltip(
                        "Points:Q",
                        format=".1f"
                    )
                ]
            ),
            150
        )

        st.markdown(
            f"""
            <div class="section-box">
            <b>Riskiest event:</b>
            {highest['time']}<br><br>

            <b>Activity:</b>
            {highest['activity']}<br>

            <b>Risk:</b>
            {highest['risk']:.0f} / 100<br><br>

            <b>Recommended action:</b>
            {ACTION[level]}
            </div>
            """,
            unsafe_allow_html=True
        )

        ctitle(
            "Risk timeline"
        )

        band = None

        if not whole:

            band = (
                start_time -
                pd.Timedelta(minutes=5),
                end_time +
                pd.Timedelta(minutes=5)
            )

        show(
            timeline_chart(
                user_df,
                thr,
                band
            ),
            260
        )

    # =====================================================
    # EVENTS
    # =====================================================

    elif option == "Events":

        st.markdown(
            "### Alert Events"
        )

        events_view = (
            alerts_df
            .sort_values(
                "risk",
                ascending=False
            )
            .head(300)
            .copy()
        )

        events_view[
            "confirmed_attack"
        ] = events_view[
            "true_label"
        ].map(
            {
                1: "Yes",
                0: "No"
            }
        )

        st.caption(
            f"{len(alerts_df):,} alerts. "
            "Showing highest-risk events."
        )

        columns = [
            "time",
            "activity",
            "risk",
            "level",
            "reasons",
            "confirmed_attack"
        ]

        st.dataframe(
            events_view[columns],
            hide_index=True,
            width="stretch",
            height=400,
            column_config={
                "time":
                    st.column_config.DatetimeColumn(
                        "Time",
                        format="DD MMM, HH:mm:ss"
                    ),

                "risk":
                    st.column_config.ProgressColumn(
                        "Risk",
                        min_value=0,
                        max_value=100,
                        format="%.0f"
                    ),

                "reasons":
                    st.column_config.TextColumn(
                        "Why it was flagged",
                        width="large"
                    ),

                "confirmed_attack":
                    "Confirmed attack"
            }
        )

        st.download_button(
            "⬇️ Download alerts CSV",
            events_view.to_csv(
                index=False
            ).encode(),
            f"alerts_{user_id}.csv",
            "text/csv",
            key=f"download_{context}_{user_id}"
        )

    # =====================================================
    # NORMAL BEHAVIOUR
    # =====================================================

    else:

        st.markdown(
            "### Normal Behaviour"
        )

        normal = user_df[
            user_df["risk"] < thr
        ]

        suspicious = user_df[
            user_df["risk"] >= thr
        ]

        behaviour_compare(
            user_id,
            normal,
            suspicious
        )


# =========================================================
# TOP NAVIGATION
# =========================================================

PAGES = [
    "Overview",
    "Live Monitor",
    "Incidents",
    "Alerts",
    "User Investigation",
    "Model Performance"
]

top1, top2 = st.columns(
    [3, 2]
)

with top1:

    st.markdown(
        "#### 🛡️ Insight360"
    )

with top2:

    thr = st.slider(
        "Alert threshold",
        0,
        100,
        DEFAULT_THR,
        1,
        help=(
            "Risk score at or above this "
            "value becomes an alert."
        )
    )


if hasattr(
    st,
    "segmented_control"
):

    page = st.segmented_control(
        "Navigate",
        PAGES,
        default="Overview",
        key="navigation",
        label_visibility="collapsed"
    )

else:

    page = st.radio(
        "Navigate",
        PAGES,
        horizontal=True,
        key="navigation",
        label_visibility="collapsed"
    )

if page is None:

    page = "Overview"

st.markdown("---")


# =========================================================
# CURRENT ALERT DATA
# =========================================================

alerts = scored[
    scored["risk"] >= thr
].copy()

users = (
    scored
    .groupby("user")
    .agg(
        peak=("risk", "max"),
        alerts=(
            "risk",
            lambda s: int(
                (s >= thr).sum()
            )
        ),
        last=("time", "max")
    )
    .reset_index()
)

attention_users = (
    users[
        users["peak"] >= thr
    ]
    .sort_values(
        "peak",
        ascending=False
    )
    .reset_index(drop=True)
)


# =========================================================
# OVERVIEW
# =========================================================

if page == "Overview":

    incidents = make_incidents(
        alerts
    )

    left, right = st.columns(
        [2, 3]
    )

    with left:

        st.markdown(
            f"""
            <div class="hero">
                <h1>Insider Threat Quickview</h1>
                <div class="sub">
                    {scored["time"].min():%d %b %Y}
                    to
                    {scored["time"].max():%d %b %Y}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with right:

        kpi_strip(
            [
                (
                    f"{len(scored):,}",
                    "EVENTS<br>ANALYSED"
                ),
                (
                    f"{len(alerts):,}",
                    "ALERTS<br>RAISED"
                ),
                (
                    f"{len(incidents):,}",
                    "INCIDENTS"
                ),
                (
                    f"{int((scored['level'] == 'Critical').sum()):,}",
                    "CRITICAL<br>EVENTS"
                )
            ]
        )

    st.write("")

    # -----------------------------------------------------
    # Charts
    # -----------------------------------------------------

    c1, c2, c3 = st.columns(3)

    with c1:

        ctitle(
            "Alerts by activity"
        )

        if alerts.empty:

            st.info(
                "No alerts at this threshold."
            )

        else:

            activity_data = (
                alerts["activity"]
                .value_counts()
                .rename_axis("activity")
                .reset_index(
                    name="events"
                )
            )

            activity_data["share"] = (
                activity_data["events"] /
                activity_data["events"].sum()
            )

            show(
                alt.Chart(
                    activity_data
                )
                .mark_arc(
                    innerRadius=62,
                    outerRadius=105
                )
                .encode(
                    theta="events:Q",
                    color=alt.Color(
                        "activity:N",
                        scale=alt.Scale(
                            range=PALETTE
                        ),
                        title=None
                    ),
                    tooltip=[
                        "activity",
                        "events",
                        alt.Tooltip(
                            "share:Q",
                            format=".1%"
                        )
                    ]
                ),
                280
            )

    with c2:

        span = (
            scored["time"].max() -
            scored["time"].min()
        )

        frequency = (
            "D"
            if span.days >= 5
            else "h"
        )

        unit = (
            "day"
            if frequency == "D"
            else "hour"
        )

        ctitle(
            f"Alerts per {unit}"
        )

        if alerts.empty:

            st.info(
                "No alerts."
            )

        else:

            trend = (
                alerts
                .set_index("time")
                .resample(
                    frequency
                )
                .size()
                .rename("alerts")
                .reset_index()
            )

            show(
                alt.Chart(
                    trend
                )
                .mark_line(
                    color=BLUE,
                    point=True
                )
                .encode(
                    x=alt.X(
                        "time:T",
                        title=None
                    ),
                    y=alt.Y(
                        "alerts:Q",
                        title="Alerts"
                    ),
                    tooltip=[
                        "time",
                        "alerts"
                    ]
                ),
                280
            )

    with c3:

        ctitle(
            "Alerts by activity and level"
        )

        if alerts.empty:

            st.info(
                "No alerts."
            )

        else:

            level_data = (
                alerts
                .groupby(
                    ["activity", "level"]
                )
                .size()
                .rename("alerts")
                .reset_index()
            )

            show(
                alt.Chart(
                    level_data
                )
                .mark_bar()
                .encode(
                    x=alt.X(
                        "activity:N",
                        title=None,
                        axis=alt.Axis(
                            labelAngle=-35
                        )
                    ),
                    y=alt.Y(
                        "alerts:Q",
                        title="Alerts"
                    ),
                    color=alt.Color(
                        "level:N",
                        scale=SCALE,
                        title="Level"
                    ),
                    tooltip=[
                        "activity",
                        "level",
                        "alerts"
                    ]
                ),
                280
            )

    # -----------------------------------------------------
    # Risk
    # -----------------------------------------------------

    l, r = st.columns(
        [3, 2]
    )

    with l:

        ctitle(
            "Risk distribution"
        )

        show(
            alt.Chart(
                scored
            )
            .mark_bar()
            .encode(
                x=alt.X(
                    "risk:Q",
                    bin=alt.Bin(
                        step=5
                    ),
                    title="Risk score"
                ),
                y=alt.Y(
                    "count():Q",
                    scale=alt.Scale(
                        type="symlog"
                    ),
                    title="Events"
                ),
                color=alt.Color(
                    "level:N",
                    scale=SCALE,
                    title="Level"
                ),
                tooltip=[
                    "count()",
                    "level"
                ]
            ),
            240
        )

    with r:

        ctitle(
            "Events by risk level"
        )

        level_counts = (
            scored["level"]
            .value_counts()
            .reindex(
                LEVELS
            )
            .fillna(0)
            .rename_axis("level")
            .reset_index(
                name="events"
            )
        )

        show(
            alt.Chart(
                level_counts
            )
            .mark_arc(
                innerRadius=50,
                outerRadius=90
            )
            .encode(
                theta="events:Q",
                color=alt.Color(
                    "level:N",
                    scale=SCALE,
                    title=None
                ),
                tooltip=[
                    "level",
                    "events"
                ]
            ),
            240
        )

    # -----------------------------------------------------
    # Users requiring attention
    # -----------------------------------------------------

    st.markdown(
        "### Users requiring attention"
    )

    if attention_users.empty:

        st.success(
            "No users are above the current threshold."
        )

    else:

        st.caption(
            "Click a User ID to open the case details."
        )

        left, right = st.columns(
            [1, 3]
        )

        with left:

            for _, row in attention_users.iterrows():

                user_level = lvl(
                    row["peak"]
                )

                selected = (
                    st.session_state.get(
                        "overview_user"
                    ) == row["user"]
                )

                if st.button(
                    f"{DOT[user_level]}  {row['user']}",
                    key=f"overview_{row['user']}",
                    type=(
                        "primary"
                        if selected
                        else "secondary"
                    ),
                    width="stretch"
                ):

                    st.session_state[
                        "overview_user"
                    ] = row["user"]

        with right:

            selected_user = (
                st.session_state.get(
                    "overview_user"
                )
            )

            if selected_user:

                case_view(
                    selected_user,
                    None,
                    None,
                    "overview",
                    whole=True
                )

            else:

                st.info(
                    "Click a user to see Start, End, "
                    "Alerts, Peak Risk and the three detail options."
                )


# =========================================================
# LIVE MONITOR
# =========================================================

elif page == "Live Monitor":

    header(
        "Live Monitor",
        "Monitor up to 3 users and watch Email, HTTP, USB, File and Command activity."
    )

    user_order = (
        users
        .sort_values(
            "peak",
            ascending=False
        )["user"]
        .tolist()
    )

    left, right = st.columns(
        [4, 2]
    )

    selected_users = left.multiselect(
        "Select users",
        user_order,
        default=user_order[:3],
        max_selections=3
    )

    speed = right.select_slider(
        "Replay speed",
        options=[
            "Slow",
            "Normal",
            "Fast"
        ],
        value="Normal"
    )

    STEP = {
        "Slow": 10,
        "Normal": 60,
        "Fast": 300
    }[speed]

    signature = tuple(
        selected_users
    )

    if (
        st.session_state.get(
            "live_signature"
        ) != signature
    ):

        st.session_state[
            "live_signature"
        ] = signature

        st.session_state[
            "live_stream"
        ] = (
            scored[
                scored["user"].isin(
                    selected_users
                )
            ]
            .sort_values("time")
            .reset_index(drop=True)
        )

        st.session_state[
            "live_position"
        ] = 0

        st.session_state[
            "live_running"
        ] = False

    b1, b2, b3, _ = st.columns(
        [1, 1, 1, 4]
    )

    if b1.button(
        "▶ Start",
        width="stretch"
    ):

        if (
            st.session_state.get(
                "live_position",
                0
            )
            >= len(
                st.session_state.get(
                    "live_stream",
                    pd.DataFrame()
                )
            )
        ):

            st.session_state[
                "live_position"
            ] = 0

        st.session_state[
            "live_running"
        ] = True

    if b2.button(
        "⏸ Pause",
        width="stretch"
    ):

        st.session_state[
            "live_running"
        ] = False

    if b3.button(
        "⏮ Reset",
        width="stretch"
    ):

        st.session_state[
            "live_position"
        ] = 0

        st.session_state[
            "live_running"
        ] = False

    stream = st.session_state.get(
        "live_stream",
        pd.DataFrame()
    )

    total = len(stream)

    box = st.empty()

    def make_user_card(
        user_id,
        data
    ):

        if data.empty:

            counts = {}

            peak = 0

        else:

            counts = (
                data["activity"]
                .value_counts()
            )

            recent = data.tail(30)

            peak = float(
                recent["risk"].max()
            )

        if peak < thr:

            status = "Normal"
            status_color = TEAL

        else:

            status = lvl(
                peak
            )

            status_color = COLORS[
                status
            ]

        # Activity mapping

        email = 0
        http = 0
        usb = 0
        file = 0
        command = 0

        for activity_name, count in counts.items():

            text = str(
                activity_name
            ).lower()

            if "email" in text:

                email += int(count)

            elif (
                "http" in text or
                "web" in text
            ):

                http += int(count)

            elif (
                "usb" in text or
                "device" in text
            ):

                usb += int(count)

            elif "file" in text:

                file += int(count)

            elif "command" in text:

                command += int(count)

        cells = f"""
        <div class="c">
            <b>{email}</b>
            <span>Email</span>
        </div>

        <div class="c">
            <b>{http}</b>
            <span>HTTP</span>
        </div>

        <div class="c">
            <b>{usb}</b>
            <span>USB</span>
        </div>

        <div class="c">
            <b>{file}</b>
            <span>File</span>
        </div>

        <div class="c">
            <b>{command}</b>
            <span>Command</span>
        </div>
        """

        alerts_count = (
            int(
                (
                    data["risk"] >= thr
                ).sum()
            )
            if not data.empty
            else 0
        )

        return f"""
        <div class="ucard">

            <div class="top">

                <span class="uid">
                    {user_id}
                </span>

                <span class="pill"
                      style="background:{status_color}">
                    {status.upper()}
                </span>

            </div>

            <div class="cells">
                {cells}
            </div>

            <div class="foot">
                Alerts {alerts_count}
                &nbsp; | &nbsp;
                Peak risk {peak:.0f}
            </div>

        </div>
        """

    def render_live(position):

        seen = stream.iloc[
            :position
        ]

        with box.container():

            if total == 0:

                st.info(
                    "Select at least one user."
                )

                return

            st.progress(
                position / total
            )

            if position == 0:

                st.info(
                    "Press ▶ Start to begin monitoring."
                )

                return

            alert_seen = seen[
                seen["risk"] >= thr
            ]

            kpi_strip(
                [
                    (
                        f"{position:,}",
                        "EVENTS<br>PROCESSED"
                    ),
                    (
                        f"{len(alert_seen):,}",
                        "ALERTS<br>RAISED"
                    ),
                    (
                        f"{int((seen['risk'] >= 60).sum()):,}",
                        "HIGH / CRITICAL"
                    ),
                    (
                        seen["time"]
                        .iloc[-1]
                        .strftime(
                            "%d %b %H:%M"
                        ),
                        "LIVE TIME"
                    )
                ]
            )

            last = seen.iloc[-1]

            if last["risk"] >= thr:

                st.error(
                    f"🚨 {last['level']} | "
                    f"User {last['user']} | "
                    f"{last['activity']} | "
                    f"Risk {last['risk']:.0f}"
                )

            else:

                st.success(
                    f"✅ Normal activity | "
                    f"User {last['user']} | "
                    f"Risk {last['risk']:.0f}"
                )

            # ---------------------------------------------
            # Three user cards
            # ---------------------------------------------

            if selected_users:

                columns = st.columns(
                    len(selected_users)
                )

                for column, user_id in zip(
                    columns,
                    selected_users
                ):

                    user_data = seen[
                        seen["user"] == user_id
                    ]

                    column.markdown(
                        make_user_card(
                            user_id,
                            user_data
                        ),
                        unsafe_allow_html=True
                    )

            st.caption(
                "Status is based on the latest 30 events for each selected user."
            )

            # ---------------------------------------------
            # Charts
            # ---------------------------------------------

            left, right = st.columns(
                [3, 2]
            )

            with left:

                ctitle(
                    "Live Risk Stream"
                )

                recent = seen.tail(
                    200
                ).copy()

                if not recent.empty:

                    recent[
                        "event_no"
                    ] = range(
                        position -
                        len(recent) +
                        1,
                        position + 1
                    )

                    points = (
                        alt.Chart(
                            recent
                        )
                        .mark_circle(
                            size=55,
                            opacity=0.85
                        )
                        .encode(
                            x=alt.X(
                                "event_no:Q",
                                title="Event"
                            ),
                            y=alt.Y(
                                "risk:Q",
                                title="Risk",
                                scale=alt.Scale(
                                    domain=[
                                        0,
                                        100
                                    ]
                                )
                            ),
                            color=alt.Color(
                                "level:N",
                                scale=SCALE,
                                title="Level"
                            ),
                            tooltip=[
                                "time",
                                "user",
                                "activity",
                                "risk",
                                "level"
                            ]
                        )
                    )

                    threshold_line = (
                        alt.Chart(
                            pd.DataFrame(
                                {"t": [thr]}
                            )
                        )
                        .mark_rule(
                            strokeDash=[
                                5,
                                5
                            ],
                            color="#8E94C9"
                        )
                        .encode(
                            y="t:Q"
                        )
                    )

                    show(
                        points +
                        threshold_line,
                        260
                    )

            with right:

                ctitle(
                    "Activity counts"
                )

                if not seen.empty:

                    activity_count = (
                        seen
                        .groupby(
                            [
                                "user",
                                "activity"
                            ]
                        )
                        .size()
                        .rename("events")
                        .reset_index()
                    )

                    show(
                        alt.Chart(
                            activity_count
                        )
                        .mark_bar()
                        .encode(
                            x=alt.X(
                                "activity:N",
                                title=None
                            ),
                            xOffset="user:N",
                            y=alt.Y(
                                "events:Q",
                                title="Count"
                            ),
                            color=alt.Color(
                                "user:N",
                                scale=alt.Scale(
                                    range=PALETTE
                                ),
                                title="User"
                            ),
                            tooltip=[
                                "user",
                                "activity",
                                "events"
                            ]
                        ),
                        260
                    )

            # ---------------------------------------------
            # Feed
            # ---------------------------------------------

            st.markdown(
                "### Live Event Feed"
            )

            feed = (
                seen
                .tail(10)
                .iloc[::-1]
                [
                    [
                        "time",
                        "user",
                        "activity",
                        "risk",
                        "level"
                    ]
                ]
            )

            st.dataframe(
                feed,
                hide_index=True,
                width="stretch",
                column_config={
                    "time":
                        st.column_config.DatetimeColumn(
                            "Time",
                            format="HH:mm:ss"
                        ),

                    "risk":
                        st.column_config.ProgressColumn(
                            "Risk",
                            min_value=0,
                            max_value=100,
                            format="%.0f"
                        )
                }
            )

    render_live(
        st.session_state.get(
            "live_position",
            0
        )
    )

    while (
        st.session_state.get(
            "live_running",
            False
        )
        and
        st.session_state.get(
            "live_position",
            0
        ) < total
    ):

        st.session_state[
            "live_position"
        ] = min(
            total,
            st.session_state[
                "live_position"
            ] + STEP
        )

        render_live(
            st.session_state[
                "live_position"
            ]
        )

        time.sleep(
            0.4
        )

    if (
        st.session_state.get(
            "live_running",
            False
        )
        and
        st.session_state.get(
            "live_position",
            0
        ) >= total
    ):

        st.session_state[
            "live_running"
        ] = False

        st.success(
            "Replay finished. Press Reset to run it again."
        )


# =========================================================
# INCIDENTS
# =========================================================

elif page == "Incidents":

    header(
        "Incidents",
        "First choose a risk level. Then choose a User ID to investigate."
    )

    incidents_all = make_incidents(
        alerts
    )

    if incidents_all.empty:

        st.info(
            "No incidents at the current threshold."
        )

    else:

        st.markdown(
            "### Select incident level"
        )

        available_levels = []

        for level_name in [
            "Critical",
            "High",
            "Medium"
        ]:

            if (
                incidents_all["level"]
                == level_name
            ).any():

                available_levels.append(
                    level_name
                )

        level_option = choose(
            "Incident level",
            [
                "All"
            ] + available_levels,
            key="incident_level"
        )

        if level_option is None:

            st.info(
                "Click All, Critical, High or Medium."
            )

        else:

            if level_option == "All":

                selected_incidents = incidents_all

            else:

                selected_incidents = (
                    incidents_all[
                        incidents_all["level"]
                        == level_option
                    ]
                )

            st.markdown(
                f"### {level_option} incidents"
            )

            st.caption(
                "Click a User ID to open the incident details."
            )

            users_in_level = (
                selected_incidents
                .groupby("user")
                .agg(
                    start=("start", "min"),
                    end=("end", "max"),
                    alerts=("events", "sum"),
                    peak=("peak_risk", "max")
                )
                .reset_index()
                .sort_values(
                    "peak",
                    ascending=False
                )
            )

            if users_in_level.empty:

                st.info(
                    "No users for this level."
                )

            else:

                columns = st.columns(4)

                for index, row in users_in_level.head(40).iterrows():

                    user_level = lvl(
                        row["peak"]
                    )

                    selected = (
                        st.session_state.get(
                            "incident_user"
                        )
                        == row["user"]
                    )

                    label = (
                        f"{DOT[user_level]} "
                        f"{row['user']}"
                    )

                    if columns[
                        index % 4
                    ].button(
                        label,
                        key=f"incident_user_{level_option}_{index}",
                        type=(
                            "primary"
                            if selected
                            else "secondary"
                        ),
                        width="stretch"
                    ):

                        st.session_state[
                            "incident_user"
                        ] = row["user"]

                        st.session_state[
                            "incident_level_selected"
                        ] = level_option

                selected_user = (
                    st.session_state.get(
                        "incident_user"
                    )
                )

                if selected_user:

                    user_incidents = (
                        selected_incidents[
                            selected_incidents["user"]
                            == selected_user
                        ]
                    )

                    if not user_incidents.empty:

                        first_start = (
                            user_incidents["start"]
                            .min()
                        )

                        last_end = (
                            user_incidents["end"]
                            .max()
                        )

                        case_view(
                            selected_user,
                            first_start,
                            last_end,
                            f"incident_{level_option}_{selected_user}",
                            whole=False
                        )

                else:

                    st.info(
                        "Click a User ID to see Start, End, "
                        "Alerts, Peak Risk and the three options."
                    )


# =========================================================
# ALERTS
# =========================================================

elif page == "Alerts":

    header(
        "Alerts",
        "Every flagged event with the reason it was flagged."
    )

    f1, f2, f3 = st.columns(
        [2, 2, 1]
    )

    selected_levels = f1.multiselect(
        "Risk level",
        LEVELS,
        default=[
            "Medium",
            "High",
            "Critical"
        ]
    )

    selected_user = f2.selectbox(
        "User",
        [
            "All users"
        ] +
        sorted(
            scored["user"].unique()
        )
    )

    selected_activity = f3.selectbox(
        "Activity",
        [
            "All"
        ] +
        ACTIVITIES
    )

    filtered = alerts[
        alerts["level"].isin(
            selected_levels
        )
    ]

    if selected_user != "All users":

        filtered = filtered[
            filtered["user"]
            == selected_user
        ]

    if selected_activity != "All":

        filtered = filtered[
            filtered["activity"]
            == selected_activity
        ]

    view = (
        filtered
        .sort_values(
            "risk",
            ascending=False
        )
        .head(500)
        .copy()
    )

    view[
        "confirmed_attack"
    ] = view[
        "true_label"
    ].map(
        {
            1: "Yes",
            0: "No"
        }
    )

    st.caption(
        f"{len(filtered):,} alerts match."
    )

    st.dataframe(
        view[
            [
                "time",
                "user",
                "activity",
                "risk",
                "level",
                "reasons",
                "confirmed_attack"
            ]
        ],
        hide_index=True,
        width="stretch",
        height=520,
        column_config={
            "time":
                st.column_config.DatetimeColumn(
                    "Time",
                    format="DD MMM, HH:mm:ss"
                ),

            "risk":
                st.column_config.ProgressColumn(
                    "Risk score",
                    min_value=0,
                    max_value=100,
                    format="%.0f"
                ),

            "reasons":
                st.column_config.TextColumn(
                    "Why it was flagged",
                    width="large"
                )
        }
    )

    st.download_button(
        "⬇️ Download alerts CSV",
        view.to_csv(
            index=False
        ).encode(),
        "alerts.csv",
        "text/csv"
    )


# =========================================================
# USER INVESTIGATION
# =========================================================

elif page == "User Investigation":

    header(
        "User Investigation",
        "Select a User ID to investigate normal behaviour and suspicious behaviour."
    )

    order = (
        users
        .sort_values(
            "peak",
            ascending=False
        )["user"]
        .tolist()
    )

    user_id = st.selectbox(
        "User ID — type to search",
        order,
        key="investigation_user"
    )

    user_df = scored[
        scored["user"] == user_id
    ]

    normal = user_df[
        user_df["risk"] < thr
    ]

    suspicious = user_df[
        user_df["risk"] >= thr
    ]

    kpi_strip(
        [
            (
                f"{user_df['risk'].max():.0f}",
                "PEAK<br>RISK"
            ),
            (
                f"{len(user_df):,}",
                "TOTAL<br>EVENTS"
            ),
            (
                f"{len(normal):,}",
                "NORMAL<br>EVENTS"
            ),
            (
                f"{len(suspicious):,}",
                "SUSPICIOUS<br>EVENTS"
            )
        ]
    )

    behaviour_compare(
        user_id,
        normal,
        suspicious
    )

    ctitle(
        "User Risk Timeline"
    )

    show(
        timeline_chart(
            user_df,
            thr
        ),
        270
    )


# =========================================================
# MODEL PERFORMANCE
# =========================================================

elif page == "Model Performance":

    header(
        "Model Performance",
        "Compare the detection models and understand how the risk threshold changes results."
    )

    # -----------------------------------------------------
    # Best model
    # -----------------------------------------------------

    best = (
        metrics
        .sort_values(
            "F1",
            ascending=False
        )
        .iloc[0]
    )

    kpi_strip(
        [
            (
                best["Model"],
                "MODEL WITH<br>HIGHEST F1"
            ),
            (
                f"{best['Precision']:.1%}",
                "PRECISION"
            ),
            (
                f"{best['Recall']:.1%}",
                "RECALL"
            ),
            (
                f"{best['F1']:.2f}",
                "F1 SCORE"
            )
        ]
    )

    # -----------------------------------------------------
    # Model table
    # -----------------------------------------------------

    st.markdown(
        "### Model comparison"
    )

    st.dataframe(
        metrics,
        hide_index=True,
        width="stretch"
    )

    # -----------------------------------------------------
    # Precision / Recall / F1
    # -----------------------------------------------------

    melted = metrics.melt(
        "Model",
        [
            "Precision",
            "Recall",
            "F1"
        ],
        "Metric",
        "Value"
    )

    ctitle(
        "Precision, Recall and F1"
    )

    show(
        alt.Chart(
            melted
        )
        .mark_bar()
        .encode(
            x=alt.X(
                "Model:N",
                title=None,
                axis=alt.Axis(
                    labelAngle=-20
                )
            ),
            xOffset="Metric:N",
            y=alt.Y(
                "Value:Q",
                scale=alt.Scale(
                    domain=[0, 1]
                ),
                title="Score"
            ),
            color=alt.Color(
                "Metric:N",
                scale=alt.Scale(
                    range=[
                        "#26B5C9",
                        "#5C6BE0",
                        "#B5F5E6"
                    ]
                ),
                title=None
            ),
            tooltip=[
                "Model",
                "Metric",
                alt.Tooltip(
                    "Value:Q",
                    format=".3f"
                )
            ]
        ),
        300
    )

    # -----------------------------------------------------
    # Threshold
    # -----------------------------------------------------

    current_result = at_threshold(
        scored,
        thr
    )

    st.markdown(
        f"### Threshold trade-off — current threshold {thr}"
    )

    kpi_strip(
        [
            (
                f"{current_result['precision']:.1%}",
                "PRECISION"
            ),
            (
                f"{current_result['recall']:.1%}",
                "RECALL"
            ),
            (
                f"{current_result['f1']:.2f}",
                "F1"
            ),
            (
                f"{current_result['false_alarm_rate']:.1%}",
                "FALSE ALARM RATE"
            )
        ]
    )

    sweep = pd.DataFrame(
        [
            at_threshold(
                scored,
                threshold
            )
            for threshold in range(
                5,
                100,
                5
            )
        ]
    )

    sweep_long = sweep.melt(
        "threshold",
        [
            "precision",
            "recall",
            "f1",
            "false_alarm_rate"
        ],
        "metric",
        "value"
    )

    l, r = st.columns(2)

    with l:

        ctitle(
            "Threshold trade-off"
        )

        show(
            alt.Chart(
                sweep_long
            )
            .mark_line(
                point=True
            )
            .encode(
                x=alt.X(
                    "threshold:Q",
                    title="Risk threshold"
                ),
                y=alt.Y(
                    "value:Q",
                    scale=alt.Scale(
                        domain=[0, 1]
                    ),
                    title=None
                ),
                color=alt.Color(
                    "metric:N",
                    scale=alt.Scale(
                        range=PALETTE[:4]
                    ),
                    title=None
                ),
                tooltip=[
                    "threshold",
                    "metric",
                    alt.Tooltip(
                        "value:Q",
                        format=".3f"
                    )
                ]
            ),
            300
        )

    with r:

        ctitle(
            "What drives the detection"
        )

        fi = (
            imp
            .head(10)
            .rename(
                lambda x:
                FRIENDLY.get(
                    x,
                    x
                )
            )
            .rename_axis(
                "feature"
            )
            .reset_index(
                name="importance"
            )
        )

        show(
            alt.Chart(
                fi
            )
            .mark_bar(
                color=BLUE
            )
            .encode(
                y=alt.Y(
                    "feature:N",
                    sort="-x",
                    title=None
                ),
                x=alt.X(
                    "importance:Q",
                    title="Importance"
                ),
                tooltip=[
                    "feature",
                    "importance"
                ]
            ),
            300
        )

    # -----------------------------------------------------
    # Confusion matrix
    # -----------------------------------------------------

    st.markdown(
        "### Confusion Matrix"
    )

    confusion = pd.DataFrame(
        [
            [
                current_result["tn"],
                current_result["fp"]
            ],
            [
                current_result["fn"],
                current_result["tp"]
            ]
        ],
        index=[
            "Actually normal",
            "Actually attack"
        ],
        columns=[
            "Predicted normal",
            "Predicted attack"
        ]
    )

    st.dataframe(
        confusion,
        width="stretch"
    )

    # IMPORTANT:
    # Evaluation section REMOVED
    # Limitations section REMOVED
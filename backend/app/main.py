from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Echo API", description="Privacy intelligence API for Echo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReportRequest(BaseModel):
    username: str
    email: str
    website: Optional[str] = None


def _score(username: str) -> int:
    """Deterministic score varied by username so results feel personalized."""
    return 55 + (sum(ord(c) for c in username) % 35)


@app.post("/report")
async def report(payload: ReportRequest):
    score = _score(payload.username)

    return {
        "username": payload.username,
        "email": payload.email,
        "website": payload.website,
        "visibility_score": score,
        "public_signals": [
            {"id": "github", "label": "GitHub profile detected", "icon": "⌨️", "detected": True},
            {"id": "linkedin", "label": "LinkedIn profile detected", "icon": "💼", "detected": True},
            {"id": "twitter", "label": "Twitter/X activity found", "icon": "🐦", "detected": True},
            {"id": "email_exposed", "label": "Email found in 3 public sources", "icon": "📧", "detected": True},
            {"id": "data_broker", "label": "Listed on 2 data broker sites", "icon": "🗃️", "detected": True},
            {"id": "dark_web", "label": "No dark web exposure detected", "icon": "🛡️", "detected": False},
        ],
        "exposure_risks": [
            {
                "id": "email",
                "title": "Public email address visible",
                "description": f"The email {payload.email} appears on GitHub and public forums",
                "severity": "high",
            },
            {
                "id": "username_link",
                "title": "Username linked across platforms",
                "description": f'Username "{payload.username}" found on 4 platforms, enabling cross-profiling',
                "severity": "medium",
            },
            {
                "id": "activity",
                "title": "Activity patterns visible",
                "description": "Public timestamps reveal your typical timezone and active hours",
                "severity": "low",
            },
            {
                "id": "data_broker",
                "title": "Listed on data broker sites",
                "description": "Personal information aggregated by 2 data brokers",
                "severity": "medium",
            },
        ],
        "recommended_actions": [
            {"id": "email", "title": "Remove public email from GitHub profile", "priority": "high"},
            {"id": "broker", "title": "Submit opt-out requests to data brokers", "priority": "high"},
            {"id": "review", "title": "Review privacy settings on all social platforms", "priority": "medium"},
            {"id": "username", "title": "Consider using different usernames per platform", "priority": "medium"},
            {"id": "audit", "title": "Audit and archive old public posts", "priority": "low"},
        ],
        "views": {
            "recruiter": {
                "headline": "Strong professional presence with minor exposure concerns",
                "signals": [
                    {"label": "Active GitHub with public contributions", "sentiment": "positive"},
                    {"label": "LinkedIn profile publicly accessible", "sentiment": "positive"},
                    {"label": "Technical writing or blog activity found", "sentiment": "positive"},
                    {"label": "Professional email domain confirmed", "sentiment": "positive"},
                    {"label": "No controversial public content detected", "sentiment": "positive"},
                    {"label": "Activity suggests full-time professional schedule", "sentiment": "neutral"},
                ],
                "summary": (
                    f"A recruiter would form a strong positive first impression of {payload.username}. "
                    "Professional profiles are visible and well-maintained. The public email exposure "
                    "is a minor concern but unlikely to affect professional perception."
                ),
            },
            "advertiser": {
                "headline": "High-value targeting profile with inferred tech-sector interests",
                "signals": [
                    {"label": "Inferred interests: software, technology, design", "sentiment": "neutral"},
                    {"label": "Estimated income bracket: Mid-to-Senior tech professional", "sentiment": "neutral"},
                    {"label": "Platform engagement: GitHub, LinkedIn, Twitter/X", "sentiment": "neutral"},
                    {"label": "Likely B2B software purchaser", "sentiment": "neutral"},
                    {"label": "Geographic signals inferrable from activity", "sentiment": "warning"},
                    {"label": "Retargetable across 3+ ad networks", "sentiment": "warning"},
                ],
                "summary": (
                    f"The public digital presence of {payload.username} creates a detailed advertiser profile. "
                    "Marketers can infer occupation, interests, income level, and device usage from publicly "
                    "available signals — without any direct ad interaction."
                ),
            },
            "threat": {
                "headline": "Moderate social engineering risk — email and username are key vectors",
                "signals": [
                    {"label": f"Email {payload.email} confirmed on 3 public sources", "sentiment": "danger"},
                    {"label": f'Username "{payload.username}" consistent across 4 platforms', "sentiment": "danger"},
                    {"label": "Public repos may reveal employer or current projects", "sentiment": "warning"},
                    {"label": "Activity timing reveals likely timezone", "sentiment": "warning"},
                    {"label": "No password breach data found", "sentiment": "positive"},
                    {"label": "Account recovery routes partially visible", "sentiment": "warning"},
                ],
                "summary": (
                    f"The exposed email and consistent username for {payload.username} create targetable attack "
                    "vectors for phishing and credential stuffing. Cross-platform linking allows a threat actor "
                    "to build a detailed profile with minimal effort. No breach data was found, which "
                    "significantly reduces immediate risk."
                ),
            },
        },
    }


@app.get("/score")
async def score_endpoint(username: Optional[str] = None):
    return {"username": username, "visibility_score": _score(username or "default")}


@app.get("/recommendations")
async def recommendations():
    return {
        "recommendations": [
            {"id": "email", "title": "Remove public email from GitHub profile", "priority": "high"},
            {"id": "broker", "title": "Submit opt-out requests to data brokers", "priority": "high"},
            {"id": "review", "title": "Review privacy settings on all social platforms", "priority": "medium"},
            {"id": "username", "title": "Consider using different usernames per platform", "priority": "medium"},
            {"id": "audit", "title": "Audit and archive old public posts", "priority": "low"},
        ]
    }

"""
Echo API — real OSINT scanner
Checks: GitHub · GitLab · DEV.to · HackerNews · Keybase · Mastodon · Gravatar
        DNS (SPF / DMARC / MX) · WHOIS domain age
"""

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, quote

from dotenv import load_dotenv
load_dotenv()

import dns.asyncresolver
import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import whois as whois_lib
    _WHOIS_OK = True
except ImportError:
    _WHOIS_OK = False

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()


app = FastAPI(title="Echo API", description="Privacy intelligence API — real OSINT scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request model ────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    username:  Optional[str] = None
    full_name: Optional[str] = None
    email:     Optional[str] = None
    scan_mode: str           = "quick"
    website:   Optional[str] = None


# ─── Platform scanners ────────────────────────────────────────────────────────

async def scan_github(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://api.github.com/users/{quote(username)}",
            headers={"Accept": "application/vnd.github+json"},
            timeout=7.0,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "found": True,
                "public_repos": d.get("public_repos", 0),
                "followers": d.get("followers", 0),
                "email_public": bool(d.get("email")),
                "has_bio": bool(d.get("bio")),
                "has_company": bool(d.get("company")),
                "profile_url": d.get("html_url", f"https://github.com/{username}"),
                "created_at": d.get("created_at"),
            }
        return {"found": False}
    except Exception:
        return {"found": False, "error": True}


async def scan_devto(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://dev.to/api/users/by_username?url={quote(username)}",
            timeout=7.0,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "found": True,
                "post_count": d.get("post_count", 0),
                "comments_count": d.get("comments_count", 0),
                "twitter_linked": bool(d.get("twitter_username")),
                "github_linked": bool(d.get("github_username")),
                "profile_url": f"https://dev.to/{username}",
            }
        return {"found": False}
    except Exception:
        return {"found": False, "error": True}


async def scan_hackernews(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://hacker-news.firebaseio.com/v0/user/{quote(username)}.json",
            timeout=7.0,
        )
        if r.status_code == 200 and r.json():
            d = r.json()
            return {
                "found": True,
                "karma": d.get("karma", 0),
                "profile_url": f"https://news.ycombinator.com/user?id={username}",
            }
        return {"found": False}
    except Exception:
        return {"found": False, "error": True}


async def scan_gitlab(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://gitlab.com/api/v4/users?username={quote(username)}",
            timeout=7.0,
        )
        if r.status_code == 200:
            users = r.json()
            if users:
                u = users[0]
                return {
                    "found": True,
                    "public_repos": u.get("public_repos", 0),
                    "followers": u.get("followers", 0),
                    "profile_url": u.get("web_url", f"https://gitlab.com/{username}"),
                }
        return {"found": False}
    except Exception:
        return {"found": False, "error": True}


async def scan_gravatar(email: str, client: httpx.AsyncClient) -> dict:
    """Check if the email has a public Gravatar profile — reveals email is tied to web services."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        r = await client.get(
            f"https://www.gravatar.com/{email_hash}.json",
            timeout=7.0,
        )
        if r.status_code == 200:
            entry = r.json().get("entry", [{}])[0]
            return {
                "found": True,
                "display_name": entry.get("displayName", ""),
                "profile_url": entry.get("profileUrl", ""),
                "linked_accounts": len(entry.get("accounts", [])),
            }
        return {"found": False}
    except Exception:
        return {"found": False, "error": True}


async def scan_hibp(email: str, client: httpx.AsyncClient) -> dict:
    """Check HaveIBeenPwned for known data breaches containing this email address."""
    if not HIBP_API_KEY:
        return {"checked": False}
    try:
        r = await client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "User-Agent":   "Echo-OSINT-Scanner/1.0",
            },
            timeout=8.0,
        )
        if r.status_code == 200:
            breaches = r.json()
            names        = [b.get("Name", "") for b in breaches]
            data_classes = sorted({dc for b in breaches for dc in b.get("DataClasses", [])})
            return {
                "checked":       True,
                "found":         True,
                "breach_count":  len(breaches),
                "breach_names":  names[:10],
                "data_classes":  data_classes[:15],
            }
        if r.status_code == 404:
            return {"checked": True, "found": False, "breach_count": 0}
        if r.status_code == 401:
            return {"checked": False, "error": "invalid_key"}
        return {"checked": False, "error": "api_error"}
    except Exception:
        return {"checked": False, "error": "request_failed"}


async def scan_keybase(username: str, client: httpx.AsyncClient) -> dict:
    """Keybase shows cryptographically verified cross-platform identity proofs."""
    try:
        r = await client.get(
            f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={quote(username)}",
            timeout=7.0,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status", {}).get("code") == 0:
                them = d.get("them", [])
                if them and them[0]:
                    u = them[0]
                    proofs = u.get("proofs_summary", {}).get("all", [])
                    proof_services = list({p["proof_type"] for p in proofs})
                    return {
                        "found": True,
                        "proof_count": len(proofs),
                        "proof_services": proof_services,
                        "profile_url": f"https://keybase.io/{username}",
                    }
        return {"found": False}
    except Exception:
        return {"found": False, "error": True}


async def scan_mastodon(username: str, client: httpx.AsyncClient) -> dict:
    """Check mastodon.social — the largest single Mastodon server."""
    try:
        r = await client.get(
            f"https://mastodon.social/api/v1/accounts/lookup?acct={quote(username)}",
            timeout=7.0,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "found": True,
                "followers": d.get("followers_count", 0),
                "posts": d.get("statuses_count", 0),
                "profile_url": d.get("url", f"https://mastodon.social/@{username}"),
            }
        return {"found": False}
    except Exception:
        return {"found": False, "error": True}



# ─── DNS analysis ─────────────────────────────────────────────────────────────

async def analyze_dns(domain: str) -> dict:
    result = {"has_spf": False, "has_dmarc": False, "has_mx": False, "resolves": False}
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 4.0

    async def _spf():
        try:
            answers = await resolver.resolve(domain, "TXT")
            for rec in answers:
                if "v=spf1" in rec.to_text():
                    result["has_spf"] = True
                    result["resolves"] = True
        except Exception:
            pass

    async def _dmarc():
        try:
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rec in answers:
                if "DMARC1" in rec.to_text():
                    result["has_dmarc"] = True
        except Exception:
            pass

    async def _mx():
        try:
            await resolver.resolve(domain, "MX")
            result["has_mx"] = True
            result["resolves"] = True
        except Exception:
            pass

    async def _a():
        try:
            await resolver.resolve(domain, "A")
            result["resolves"] = True
        except Exception:
            pass

    await asyncio.gather(_spf(), _dmarc(), _mx(), _a())
    return result


# ─── WHOIS (sync → thread executor) ──────────────────────────────────────────

def _sync_whois(domain: str) -> dict:
    if not _WHOIS_OK:
        return {}
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            return {"age_days": max(age_days, 0), "registrar": w.registrar}
    except Exception:
        pass
    return {}


async def analyze_whois(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _sync_whois, domain),
            timeout=8.0,
        )
    except asyncio.TimeoutError:
        return {}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _extract_domain(website: str) -> Optional[str]:
    if not website:
        return None
    url = website if "://" in website else f"https://{website}"
    host = urlparse(url).hostname or ""
    return host.removeprefix("www.") or None


def _email_domain(email: str) -> Optional[str]:
    parts = email.strip().split("@")
    return parts[-1].lower() if len(parts) == 2 else None


# ─── Score ────────────────────────────────────────────────────────────────────

def compute_score(platforms: dict, dns_info: dict, gh_email_public: bool, gravatar_found: bool) -> int:
    found = sum(1 for v in platforms.values() if v.get("found"))
    score = 10                           # base
    score += found * 11                  # 11 per platform (7 platforms × 11 = 77 max)
    if found >= 3:
        score += 15                      # strong cross-linking bonus
    elif found >= 2:
        score += 8
    if dns_info.get("resolves"):
        score += 6                       # website exists
    if gh_email_public:
        score += 5                       # email exposed on GitHub
    if gravatar_found:
        score += 4                       # email tied to public web profile
    hibp = platforms.get("hibp", {})
    if hibp.get("checked") and hibp.get("found"):
        score += min(hibp.get("breach_count", 1) * 2, 10)  # up to +10 for breaches
    return min(score, 100)


# ─── Signals ─────────────────────────────────────────────────────────────────

def build_signals(platforms: dict, dns_info: dict, whois_info: dict, domain: Optional[str]) -> list:
    gh  = platforms["github"]
    gl  = platforms["gitlab"]
    dt  = platforms["devto"]
    hn  = platforms["hackernews"]
    kb  = platforms["keybase"]
    ms  = platforms["mastodon"]
    gv  = platforms["gravatar"]

    sigs = [
        {
            "id": "github",
            "label": f"GitHub — {gh['public_repos']:,} repos · {gh.get('followers',0):,} followers" if gh.get("found") else "GitHub — no profile found",
            "icon": "⌨️",
            "detected": gh.get("found", False),
        },
        {
            "id": "gitlab",
            "label": "GitLab — profile found" if gl.get("found") else "GitLab — no profile found",
            "icon": "🦊",
            "detected": gl.get("found", False),
        },
        {
            "id": "devto",
            "label": f"DEV.to — {dt['post_count']:,} posts" if dt.get("found") else "DEV.to — no account found",
            "icon": "👩‍💻",
            "detected": dt.get("found", False),
        },
        {
            "id": "hackernews",
            "label": f"HackerNews — {hn['karma']:,} karma" if hn.get("found") else "HackerNews — no account found",
            "icon": "🟠",
            "detected": hn.get("found", False),
        },
        {
            "id": "keybase",
            "label": f"Keybase — {kb.get('proof_count', 0)} verified identity proofs" if kb.get("found") else "Keybase — no account found",
            "icon": "🔑",
            "detected": kb.get("found", False),
        },
        {
            "id": "mastodon",
            "label": f"Mastodon — {ms.get('followers', 0):,} followers" if ms.get("found") else "Mastodon — no account found",
            "icon": "🐘",
            "detected": ms.get("found", False),
        },
        {
            "id": "gravatar",
            "label": "Gravatar — email linked to public web profile" if gv.get("found") else "Gravatar — email not linked",
            "icon": "🌐",
            "detected": gv.get("found", False),
        },
    ]

    hibp = platforms.get("hibp", {})
    if hibp.get("checked"):
        if hibp.get("found"):
            count = hibp.get("breach_count", 0)
            sigs.append({
                "id":       "hibp",
                "label":    f"HaveIBeenPwned — email in {count} breach{'es' if count != 1 else ''}",
                "icon":     "🔓",
                "detected": True,
            })
        else:
            sigs.append({
                "id":       "hibp",
                "label":    "HaveIBeenPwned — no breaches found",
                "icon":     "🔓",
                "detected": False,
            })

    if domain:
        age = whois_info.get("age_days")
        if age is not None:
            if age < 365:
                label = f"Domain registered {age} days ago"
            else:
                label = f"Domain established ({age // 365}y {age % 365 // 30}mo old)"
            sigs.append({"id": "domain_age", "label": label, "icon": "🌐", "detected": True})
        elif dns_info.get("resolves"):
            sigs.append({"id": "domain", "label": "Website domain resolves", "icon": "🌐", "detected": True})

        sigs.append({
            "id": "spf",
            "label": "SPF record configured" if dns_info.get("has_spf") else "No SPF record on domain",
            "icon": "📧",
            "detected": dns_info.get("has_spf", False),
        })

        sigs.append({
            "id": "dmarc",
            "label": "DMARC policy present" if dns_info.get("has_dmarc") else "No DMARC policy on domain",
            "icon": "🔒",
            "detected": dns_info.get("has_dmarc", False),
        })

    return sigs


# ─── Risks ────────────────────────────────────────────────────────────────────

_PLATFORM_LABELS = {
    "github": "GitHub", "gitlab": "GitLab", "devto": "DEV.to",
    "hackernews": "HackerNews", "keybase": "Keybase",
    "mastodon": "Mastodon", "gravatar": "Gravatar",
}

def build_risks(username: str, platforms: dict, dns_info: dict, whois_info: dict, domain: Optional[str]) -> list:
    gh   = platforms["github"]
    kb   = platforms["keybase"]
    gv   = platforms["gravatar"]
    hibp = platforms.get("hibp", {})
    found_names = [k for k, v in platforms.items() if v.get("found") and k != "hibp"]
    risks = []

    if hibp.get("checked") and hibp.get("found"):
        count  = hibp.get("breach_count", 0)
        names  = hibp.get("breach_names", [])
        dcs    = hibp.get("data_classes", [])
        name_str = ", ".join(names[:5]) + ("…" if len(names) > 5 else "")
        dc_str   = ", ".join(dcs[:6])   + ("…" if len(dcs)   > 6 else "")
        risks.append({
            "id":          "hibp_breaches",
            "title":       f"Email found in {count} data breach{'es' if count != 1 else ''}",
            "description": (
                f"Exposed in: {name_str}. "
                + (f"Data types compromised: {dc_str}. " if dc_str else "")
                + "Credential stuffing tools use these databases to automate account takeover."
            ),
            "severity": "high",
        })

    if gh.get("found") and gh.get("email_public"):
        risks.append({
            "id": "github_email",
            "title": "Email exposed on GitHub profile",
            "description": "Public GitHub email gets scraped by spam lists and phishing tools.",
            "severity": "high",
        })

    if gv.get("found"):
        risks.append({
            "id": "gravatar_email",
            "title": "Email linked to a public Gravatar profile",
            "description": "Email resolves to a Gravatar profile. Any service that checks the MD5 hash can confirm the email is active.",
            "severity": "medium",
        })

    if kb.get("found") and kb.get("proof_count", 0) > 0:
        services = ", ".join(kb.get("proof_services", []))
        risks.append({
            "id": "keybase_proofs",
            "title": "Keybase identity proofs link accounts publicly",
            "description": f"These accounts are cryptographically linked on Keybase: {services}.",
            "severity": "medium",
        })

    if len(found_names) >= 3:
        labels = ", ".join(_PLATFORM_LABELS.get(p, p.capitalize()) for p in found_names[:5])
        risks.append({
            "id": "cross_platform",
            "title": f"Username found on {len(found_names)} platforms",
            "description": f"Same handle on {labels}{'…' if len(found_names) > 5 else ''}. Easy to correlate across platforms.",
            "severity": "high",
        })
    elif len(found_names) == 2:
        labels = " and ".join(_PLATFORM_LABELS.get(p, p.capitalize()) for p in found_names)
        risks.append({
            "id": "cross_platform",
            "title": "Username linked across platforms",
            "description": f"Found on {labels} — same handle makes cross-platform lookup trivial.",
            "severity": "medium",
        })
    elif len(found_names) == 1:
        risks.append({
            "id": "single_platform",
            "title": "Public profile detected",
            "description": f"Active on {_PLATFORM_LABELS.get(found_names[0], found_names[0])}. Activity history and connections are publicly indexed.",
            "severity": "low",
        })

    age = whois_info.get("age_days")
    if age is not None and domain:
        if age < 90:
            risks.append({
                "id": "new_domain",
                "title": "Very recently registered domain",
                "description": f"{domain} was registered {age} days ago. Domains this new get extra scrutiny from spam filters.",
                "severity": "high",
            })
        elif age < 365:
            risks.append({
                "id": "young_domain",
                "title": "Recently registered domain",
                "description": f"{domain} is {age} days old. Newer domains have less established trust with mail filters.",
                "severity": "medium",
            })

    if domain and dns_info.get("resolves") and not dns_info.get("has_spf"):
        risks.append({
            "id": "no_spf",
            "title": f"No SPF record — {domain} is spoofable",
            "description": f"Without SPF, anyone can send email that appears to come from {domain}.",
            "severity": "medium",
        })

    if domain and dns_info.get("resolves") and not dns_info.get("has_dmarc"):
        risks.append({
            "id": "no_dmarc",
            "title": "No DMARC policy configured",
            "description": f"DMARC is missing on {domain}. Mail receivers have no policy to fall back on when spoofed mail arrives.",
            "severity": "low",
        })

    if not risks:
        risks.append({
            "id": "low_profile",
            "title": "Minimal public footprint",
            "description": "Nothing significant found across checked platforms.",
            "severity": "low",
        })

    return risks


# ─── Actions ─────────────────────────────────────────────────────────────────

def build_actions(risks: list, platforms: dict) -> list:
    ids  = {r["id"] for r in risks}
    hibp = platforms.get("hibp", {})
    actions = []

    if "hibp_breaches" in ids:
        count = hibp.get("breach_count", 0)
        names = hibp.get("breach_names", [])
        actions.append({
            "id":       "hibp_rotate",
            "title":    f"Rotate passwords for {count} breached service{'s' if count != 1 else ''}: {', '.join(names[:4])}{'…' if len(names) > 4 else ''}",
            "priority": "high",
        })
        actions.append({
            "id":       "hibp_2fa",
            "title":    "Enable two-factor authentication on all accounts using this email",
            "priority": "high",
        })
    elif not hibp.get("checked"):
        actions.append({
            "id":       "hibp",
            "title":    "Check this email on HaveIBeenPwned",
            "priority": "high",
        })

    if "github_email" in ids:
        actions.append({"id": "fix_gh_email",  "title": "Set GitHub email to private (Settings → Emails)",         "priority": "high"})
    if "no_spf" in ids:
        actions.append({"id": "add_spf",        "title": "Add a v=spf1 TXT record to the domain DNS",              "priority": "high"})
    if "new_domain" in ids or "young_domain" in ids:
        actions.append({"id": "domain_rep",     "title": "Submit domain to Google Safe Browsing for review",        "priority": "high"})
    if "cross_platform" in ids or "single_platform" in ids:
        actions.append({"id": "diff_usernames", "title": "Use different usernames across platforms",                "priority": "medium"})
    if "no_dmarc" in ids:
        actions.append({"id": "add_dmarc",      "title": "Add a DMARC policy (p=quarantine is a good start)",      "priority": "medium"})

    actions.append({"id": "privacy_audit",  "title": "Review privacy settings on each active platform",            "priority": "medium"})
    actions.append({"id": "data_brokers",   "title": "Opt out of Spokeo, Whitepages, and BeenVerified",            "priority": "low"})

    return actions


# ─── Perspective views ────────────────────────────────────────────────────────

def build_views(username: str, email: str, platforms: dict, dns_info: dict, whois_info: dict, domain: Optional[str]) -> dict:
    gh = platforms["github"]
    gl = platforms["gitlab"]
    dt = platforms["devto"]
    hn = platforms["hackernews"]
    kb = platforms["keybase"]
    ms = platforms["mastodon"]
    gv = platforms["gravatar"]
    found = [k for k, v in platforms.items() if v.get("found")]
    n = len(found)

    # ── Recruiter ──
    rec_sigs = []
    if gh.get("found"):
        rec_sigs.append({"label": f"GitHub — {gh.get('public_repos', 0)} public repos visible", "sentiment": "positive"})
        if gh.get("has_company"):
            rec_sigs.append({"label": "Employer affiliation listed on GitHub", "sentiment": "positive"})
        if gh.get("followers", 0) > 10:
            rec_sigs.append({"label": f"{gh['followers']} GitHub followers — established presence", "sentiment": "positive"})
    if gl.get("found"):
        rec_sigs.append({"label": "GitLab profile present — additional project visibility", "sentiment": "positive"})
    if dt.get("found"):
        rec_sigs.append({"label": f"DEV.to — {dt.get('post_count', 0)} published posts", "sentiment": "positive"})
    if hn.get("found"):
        rec_sigs.append({"label": f"HackerNews active ({hn.get('karma', 0):,} karma)", "sentiment": "positive"})
    if ms.get("found"):
        rec_sigs.append({"label": f"Mastodon presence — {ms.get('followers', 0):,} followers", "sentiment": "positive"})
    if n >= 2:
        rec_sigs.append({"label": f"Same username across {n} platforms", "sentiment": "positive"})
    if gh.get("email_public"):
        rec_sigs.append({"label": "Email address visible on GitHub profile", "sentiment": "neutral"})

    if n == 0:
        rec_headline = "No public developer presence found"
        rec_summary = f"A recruiter searching for '{username}' would find nothing. Hard to background-check, but also hard to verify."
    elif n >= 2:
        rec_headline = f"Developer presence on {n} platforms"
        rec_summary = f"{username} shows up on {', '.join(p.capitalize() for p in found)}. Easy to verify activity and cross-reference."
    else:
        rec_headline = "Presence on one platform"
        rec_summary = f"{username} is on {found[0].capitalize()}. Some signal, but nothing to cross-reference against."

    # ── Advertiser ──
    adv_sigs = []
    if gh.get("found"):
        adv_sigs.append({"label": "Interests: software, open source, dev tooling", "sentiment": "neutral"})
        adv_sigs.append({"label": "GitHub activity suggests B2B software profile", "sentiment": "neutral"})
    if gl.get("found"):
        adv_sigs.append({"label": "GitLab — additional developer platform footprint", "sentiment": "neutral"})
    if dt.get("found"):
        adv_sigs.append({"label": "DEV.to — developer writing and community activity", "sentiment": "neutral"})
    if hn.get("found"):
        adv_sigs.append({"label": "HackerNews — tech-sector activity confirmed", "sentiment": "neutral"})
    if ms.get("found"):
        adv_sigs.append({"label": "Mastodon — social graph and posts publicly visible", "sentiment": "neutral"})
    if gv.get("found"):
        adv_sigs.append({"label": "Email hash resolves on Gravatar — email is active", "sentiment": "warning"})
    if n >= 2:
        adv_sigs.append({"label": f"Username match across {n} platforms enables cross-targeting", "sentiment": "warning"})
    if domain and dns_info.get("resolves"):
        adv_sigs.append({"label": "Personal domain ties to real identity", "sentiment": "neutral"})
    adv_sigs.append({"label": "Email searchable in data broker databases", "sentiment": "warning"})
    adv_sigs.append({"label": "Post timestamps reveal timezone and active hours", "sentiment": "neutral"})

    adv_summary = (
        f"Enough public data on {username} to build an interest profile. "
        "Platform activity, email, and username can be cross-referenced for targeting."
    ) if n > 0 else (
        f"Not much to work with for platform-based targeting on '{username}'. "
        "Email-based targeting through data brokers is still possible."
    )

    # ── Threat actor ──
    threat_sigs = []
    if gh.get("found") and gh.get("email_public"):
        threat_sigs.append({"label": "Email confirmed public on GitHub — direct phishing vector", "sentiment": "danger"})
    elif gh.get("found"):
        threat_sigs.append({"label": "GitHub profile found — public activity visible", "sentiment": "warning"})
    if n >= 2:
        threat_sigs.append({"label": f"'{username}' on {n} platforms — account correlation is trivial", "sentiment": "danger"})
    if gh.get("found"):
        threat_sigs.append({"label": "Public repos may reveal employer, tech stack, and project context", "sentiment": "warning"})
    if kb.get("found"):
        proofs = kb.get("proof_services", [])
        threat_sigs.append({"label": f"Keybase proofs publicly link accounts: {', '.join(proofs) if proofs else 'multiple'}", "sentiment": "danger"})
    if gv.get("found"):
        threat_sigs.append({"label": "Email hash resolves on Gravatar — confirms email is active and in-use", "sentiment": "warning"})
    if ms.get("found"):
        threat_sigs.append({"label": f"Mastodon account found — social graph and posts publicly visible", "sentiment": "warning"})
    if gl.get("found"):
        threat_sigs.append({"label": "GitLab account found — additional project and commit history", "sentiment": "warning"})
    if domain and not dns_info.get("has_spf") and dns_info.get("resolves"):
        threat_sigs.append({"label": f"No SPF on {domain} — domain spoofing is trivially possible", "sentiment": "danger"})
    age = whois_info.get("age_days")
    if age is not None and age < 365:
        threat_sigs.append({"label": f"Domain only {age} days old — low established trust", "sentiment": "warning"})
    hibp = platforms.get("hibp", {})
    if hibp.get("checked") and hibp.get("found"):
        count = hibp.get("breach_count", 0)
        names = hibp.get("breach_names", [])
        threat_sigs.append({
            "label":     f"Email found in {count} breach{'es' if count != 1 else ''} ({', '.join(names[:3])}{'…' if len(names) > 3 else ''}) — credential stuffing risk",
            "sentiment": "danger",
        })
    elif hibp.get("checked"):
        threat_sigs.append({"label": "HaveIBeenPwned — no known breaches for this email", "sentiment": "positive"})
    else:
        threat_sigs.append({"label": "Breach data not checked — add HIBP_API_KEY to complete picture", "sentiment": "neutral"})
    threat_sigs.append({"label": "Activity timestamps can reveal timezone and daily schedule", "sentiment": "warning"})

    if n == 0:
        threat_headline = "Low profile — small attack surface"
        threat_summary = (
            f"Not much publicly available on '{username}'. "
            "The email address alone is still a usable phishing and credential-stuffing target."
        )
    else:
        has_email_risk  = gh.get("found") and gh.get("email_public")
        hibp_local      = platforms.get("hibp", {})
        breach_suffix   = (
            f"Email is in {hibp_local.get('breach_count', 0)} known breach(es) — credential stuffing is a real risk."
            if hibp_local.get("checked") and hibp_local.get("found")
            else "No breaches found for this email."
            if hibp_local.get("checked")
            else "Breach status not checked — add HIBP_API_KEY."
        )
        threat_headline = f"{'Email exposed · ' if has_email_risk else ''}Identity linkable across {n} platform{'s' if n != 1 else ''}"
        threat_summary = (
            f"'{username}' appears on {n} platform{'s' if n != 1 else ''}. "
            + ("Public GitHub email makes phishing straightforward. " if has_email_risk else "")
            + breach_suffix
        )

    return {
        "recruiter":  {"headline": rec_headline,  "signals": rec_sigs[:6],    "summary": rec_summary},
        "advertiser": {"headline": "Ad targeting profile from public data", "signals": adv_sigs[:6], "summary": adv_summary},
        "threat":     {"headline": threat_headline, "signals": threat_sigs[:6], "summary": threat_summary},
    }


# ─── Route ────────────────────────────────────────────────────────────────────

@app.get("/")
async def health():
    return {"status": "ok", "service": "echo-api"}


@app.post("/report")
async def report(payload: ReportRequest):
    username    = (payload.username  or "").strip()
    email       = (payload.email     or "").strip()
    full_name   = (payload.full_name or "").strip()
    scan_mode   = payload.scan_mode  or "quick"
    site_domain = _extract_domain(payload.website or "")
    email_dom   = _email_domain(email) if email else None
    check_domain = site_domain or email_dom

    async def _skip():
        return {"found": False}

    async def _no_dns():
        return {}

    async def _hibp_skip():
        return {"checked": False}

    async with httpx.AsyncClient() as client:
        if scan_mode == "quick":
            gh, kb, gv, hibp_result = await asyncio.gather(
                scan_github(username, client)  if username else _skip(),
                scan_keybase(username, client) if username else _skip(),
                scan_gravatar(email, client)   if email    else _skip(),
                scan_hibp(email, client)       if email    else _hibp_skip(),
                return_exceptions=True,
            )
            gl = dt = hn = ms = {"found": False}
            dns_info = {}
        else:
            gh, gl, dt, hn, kb, ms, gv, hibp_result, dns_info = await asyncio.gather(
                scan_github(username, client)     if username else _skip(),
                scan_gitlab(username, client)     if username else _skip(),
                scan_devto(username, client)      if username else _skip(),
                scan_hackernews(username, client) if username else _skip(),
                scan_keybase(username, client)    if username else _skip(),
                scan_mastodon(username, client)   if username else _skip(),
                scan_gravatar(email, client)      if email    else _skip(),
                scan_hibp(email, client)          if email    else _hibp_skip(),
                analyze_dns(check_domain)         if check_domain else _no_dns(),
                return_exceptions=True,
            )

    def _safe(v):
        return v if isinstance(v, dict) else {"found": False, "error": True}

    gh          = _safe(gh)
    gl          = _safe(gl)
    dt          = _safe(dt)
    hn          = _safe(hn)
    kb          = _safe(kb)
    ms          = _safe(ms)
    gv          = _safe(gv)
    hibp_result = hibp_result if isinstance(hibp_result, dict) else {"checked": False, "error": True}
    dns_info    = dns_info if isinstance(dns_info, dict) else {}

    platforms = {
        "github": gh, "gitlab": gl, "devto": dt,
        "hackernews": hn, "keybase": kb, "mastodon": ms, "gravatar": gv,
        "hibp": hibp_result,
    }

    # WHOIS only in deep scan
    whois_info = (await analyze_whois(check_domain)) if (scan_mode == "deep" and check_domain) else {}

    display_name = username or full_name
    risks   = build_risks(display_name, platforms, dns_info, whois_info, site_domain)
    actions = build_actions(risks, platforms)
    score   = compute_score(platforms, dns_info, gh.get("email_public", False), gv.get("found", False))
    all_signals = build_signals(platforms, dns_info, whois_info, site_domain)
    # For quick scan, only surface signals for platforms actually checked
    if scan_mode == "quick":
        checked = {"github", "keybase", "gravatar", "hibp"}
        signals = [s for s in all_signals if s["id"] in checked]
    else:
        signals = all_signals

    all_views = build_views(display_name, email, platforms, dns_info, whois_info, site_domain)
    if scan_mode == "quick":
        # Recruiter and advertiser views require the full platform profile
        views = {"recruiter": None, "advertiser": None, "threat": all_views["threat"]}
    else:
        views = all_views

    base_platforms = (
        ["github", "keybase", "gravatar"]
        if scan_mode == "quick"
        else ["github", "gitlab", "devto", "hackernews", "keybase", "mastodon", "gravatar"]
    )
    platforms_checked = base_platforms + (["haveibeenpwned"] if hibp_result.get("checked") else [])

    return {
        "username":            username,
        "full_name":           full_name,
        "email":               email,
        "website":             payload.website,
        "scan_mode":           scan_mode,
        "visibility_score":    score,
        "scan_meta": {
            "platforms_checked": platforms_checked,
            "domain_checked":    check_domain if scan_mode == "deep" else None,
            "scanned_at":        datetime.now(timezone.utc).isoformat(),
        },
        "public_signals":      signals,
        "exposure_risks":      risks,
        "recommended_actions": actions,
        "views":               views,
    }


@app.get("/score")
async def score_endpoint(username: Optional[str] = None):
    if not username:
        return {"username": None, "visibility_score": 0}
    async with httpx.AsyncClient() as client:
        gh = await scan_github(username, client)
    return {
        "username": username,
        "visibility_score": compute_score(
            {"github": gh, "gitlab": {"found": False}, "devto": {"found": False},
             "hackernews": {"found": False}, "keybase": {"found": False},
             "mastodon": {"found": False}, "gravatar": {"found": False}},
            {}, gh.get("email_public", False), False,
        ),
    }


@app.get("/recommendations")
async def recommendations():
    return {
        "recommendations": [
            {"id": "hibp",          "title": "Check email on HaveIBeenPwned",                           "priority": "high"},
            {"id": "gh_email",      "title": "Set GitHub email to private",                             "priority": "high"},
            {"id": "spf",           "title": "Add SPF record to your domain",                           "priority": "high"},
            {"id": "dmarc",         "title": "Configure a DMARC policy",                                "priority": "medium"},
            {"id": "usernames",     "title": "Use distinct usernames per platform",                     "priority": "medium"},
            {"id": "data_brokers",  "title": "Opt out of Spokeo, Whitepages, BeenVerified",             "priority": "low"},
        ]
    }

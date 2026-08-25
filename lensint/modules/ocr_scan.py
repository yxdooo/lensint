"""Optical Character Recognition (OCR) and Sensitive Data / Credential Leak Scanner.

Extracts text from screenshots, documents, and images to uncover leaked secrets,
API tokens, credentials, private keys, credit cards, and PII.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from PIL import Image

from lensint.core.models import OCRReport


# Common BIP39 seed words sample
BIP39_SAMPLE = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused",
    "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle",
    "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
    "any", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around",
    "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork",
    "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august",
    "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor",
    "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
    "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
    "battle", "beach", "bean", "beauty", "because", "become", "beef", "before",
    "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
    "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame",
    "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse",
    "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone",
    "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom",
    "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave",
    "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk",
    "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush",
    "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet",
    "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage",
    "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy",
    "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain",
    "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "cast", "casual", "cat", "catalog", "catch", "category", "cattle",
    "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census",
    "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos",
    "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef",
    "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose",
    "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen",
    "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk",
    "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock",
    "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch",
    "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect",
    "color", "column", "combine", "come", "comfort", "comic", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "consider", "control",
    "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover",
    "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater",
    "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime",
    "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel",
    "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture",
    "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion",
    "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger",
    "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris",
    "decade", "december", "decide", "decline", "decorate", "decrease", "deer",
    "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise",
    "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy",
    "derive", "describe", "desert", "design", "desk", "despair", "destroy",
    "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond",
    "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma",
    "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease",
    "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
    "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
    "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
    "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune",
    "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle",
    "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology",
    "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
    "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
    "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy",
    "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
    "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
    "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude",
    "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
    "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint",
    "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy",
    "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite",
    "feature", "february", "federal", "fee", "feed", "feel", "female", "fence",
    "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure",
    "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire",
    "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame",
    "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor",
    "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold",
    "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune",
    "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame",
    "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown",
    "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future",
    "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage",
    "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge",
    "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost",
    "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad",
    "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory",
    "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla",
    "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant",
    "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit",
    "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand",
    "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
    "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet",
    "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire",
    "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home",
    "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "house", "hover", "hub", "huge", "human", "humble", "humor",
    "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid",
    "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal",
    "illness", "image", "imitate", "immense", "immune", "impact", "impose",
    "improve", "impulse", "inch", "include", "income", "increase", "index",
    "indicate", "indoor", "industry", "infant", "inflict", "inform", "initial",
    "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry",
    "insane", "insect", "inside", "inspire", "install", "intact", "interest",
    "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue",
    "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans",
    "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice",
    "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep",
    "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss",
    "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock",
    "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
    "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
    "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
    "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
    "library", "license", "life", "lift", "light", "like", "limb", "limit",
    "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
    "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
    "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
    "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
    "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate",
    "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
    "market", "marriage", "mask", "mass", "master", "match", "material", "math",
    "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat",
    "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention",
    "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal",
    "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum",
    "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
    "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor",
    "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito",
    "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much",
    "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
    "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
    "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
    "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
    "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old",
    "olive", "olympic", "omit", "once", "one", "onion", "online", "only",
    "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard",
    "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
    "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
    "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
    "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
    "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peach",
    "peacock", "peak", "peanut", "pear", "peasant", "pelican", "pen", "penalty",
    "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone",
    "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig",
    "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch",
    "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge",
    "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police",
    "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
    "potato", "pottery", "poverty", "powder", "power", "practice", "praise",
    "predict", "prefer", "prepare", "present", "pretty", "prevent", "price",
    "pride", "primary", "print", "priority", "prison", "private", "prize", "problem",
    "process", "produce", "profit", "program", "project", "promote", "proof",
    "property", "prosper", "protect", "proud", "provide", "public", "pudding",
    "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase",
    "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality",
    "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit",
    "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally",
    "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven",
    "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall",
    "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform",
    "refuse", "region", "regret", "regular", "reject", "relax", "release",
    "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew",
    "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue",
    "resemble", "resist", "resource", "response", "result", "retire", "retreat",
    "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon",
    "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot",
    "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot",
    "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate",
    "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run",
    "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad",
    "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy",
    "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare",
    "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion",
    "scout", "scrap", "scream", "screen", "script", "scrub", "sea", "search",
    "season", "seat", "second", "secret", "section", "security", "seed", "seek",
    "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
    "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
    "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam",
    "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot",
    "slow", "slum", "small", "smart", "smile", "smoke", "smooth", "snack",
    "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock",
    "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone",
    "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south",
    "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell",
    "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
    "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring",
    "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage",
    "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel",
    "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach",
    "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong",
    "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit",
    "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure",
    "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
    "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task",
    "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis",
    "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory",
    "there", "they", "thing", "this", "thought", "three", "thrive", "throw",
    "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time",
    "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
    "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone",
    "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch",
    "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
    "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap",
    "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe",
    "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true",
    "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble",
    "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice",
    "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable",
    "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy",
    "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual",
    "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban",
    "urge", "usage", "use", "used", "useful", "useless", "usual", "utility",
    "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish",
    "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture",
    "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable",
    "vibrant", "vicious", "victory", "video", "view", "village", "vintage",
    "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid",
    "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage",
    "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior",
    "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear",
    "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west",
    "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper",
    "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing",
    "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness",
    "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry",
    "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard",
    "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"
}


# Luhn Algorithm for Credit Card validation
def _luhn_checksum(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Turkish National ID (TC Kimlik) Validation
def _validate_tc_kimlik(tc_str: str) -> bool:
    if not tc_str.isdigit() or len(tc_str) != 11 or tc_str[0] == "0":
        return False
    digits = [int(c) for c in tc_str]
    d1_9_odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    d1_9_even = digits[1] + digits[3] + digits[5] + digits[7]
    d10 = ((d1_9_odd * 7) - d1_9_even) % 10
    d11 = sum(digits[:10]) % 10
    return digits[9] == d10 and digits[10] == d11


def _redact_secret(s: str) -> str:
    """Mask confidential token/secret for safe reporting."""
    if len(s) <= 8:
        return "****"
    return s[:4] + ("*" * (len(s) - 8)) + s[-4:]


def _extract_text_heuristic(pil_img: Optional[Image.Image]) -> Tuple[str, str]:
    """Extract text from image using Tesseract/EasyOCR if available, or heuristic."""
    if pil_img is None:
        return "", "None"

    # 1. Try pytesseract if installed
    try:
        import pytesseract  # type: ignore
        text = pytesseract.image_to_string(pil_img)
        if text and len(text.strip()) > 3:
            return text.strip(), "Tesseract OCR"
    except Exception:
        pass

    # 2. Try easyocr if installed
    try:
        import easyocr  # type: ignore
        import numpy as np
        reader = easyocr.Reader(["en"], verbose=False, gpu=False)
        results = reader.readtext(np.array(pil_img.convert("RGB")))
        text = "\n".join([res[1] for res in results])
        if text and len(text.strip()) > 3:
            return text.strip(), "EasyOCR"
    except Exception:
        pass

    return "", "Builtin Heuristic"


def scan_sensitive_leaks(text: str) -> Dict[str, Any]:
    """Scan extracted OCR / string text for high-risk confidential leaks and secrets."""
    results: Dict[str, Any] = {
        "findings": [],
        "api_keys": [],
        "passwords": [],
        "tokens": [],
        "pii": [],
        "private_keys": [],
    }

    if not text:
        return results

    # 1. AWS Access Keys
    aws_keys = re.findall(r"\b(AKIA[0-9A-Z]{16})\b", text)
    for k in set(aws_keys):
        results["api_keys"].append(f"AWS Access Key: {_redact_secret(k)}")
        results["findings"].append({
            "type": "AWS Access Key ID",
            "value": k,
            "redacted": _redact_secret(k),
            "severity": "CRITICAL",
        })

    # 2. GitHub Tokens
    gh_tokens = re.findall(r"\b(gh[pousr]_[A-Za-z0-9_]{36,82}|github_pat_[A-Za-z0-9_]{82})\b", text)
    for g in set(gh_tokens):
        results["api_keys"].append(f"GitHub Token: {_redact_secret(g)}")
        results["findings"].append({
            "type": "GitHub Personal Access Token",
            "value": g,
            "redacted": _redact_secret(g),
            "severity": "CRITICAL",
        })

    # 3. OpenAI API Keys
    openai_keys = re.findall(r"\b(sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9_-]{40,})\b", text)
    for o in set(openai_keys):
        results["api_keys"].append(f"OpenAI API Key: {_redact_secret(o)}")
        results["findings"].append({
            "type": "OpenAI Secret Key",
            "value": o,
            "redacted": _redact_secret(o),
            "severity": "CRITICAL",
        })

    # 4. Slack Tokens
    slack_tokens = re.findall(r"\b(xox[baprs]-[0-9A-Za-z]{10,48})\b", text)
    for s in set(slack_tokens):
        results["tokens"].append(f"Slack API Token: {_redact_secret(s)}")
        results["findings"].append({
            "type": "Slack Token",
            "value": s,
            "redacted": _redact_secret(s),
            "severity": "HIGH",
        })

    # 5. JWT Tokens
    jwt_tokens = re.findall(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b", text)
    for j in set(jwt_tokens):
        results["tokens"].append(f"JWT Token: {_redact_secret(j)}")
        results["findings"].append({
            "type": "JSON Web Token (JWT)",
            "value": j,
            "redacted": _redact_secret(j),
            "severity": "HIGH",
        })

    # 6. Private Keys
    priv_keys = re.findall(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", text, re.IGNORECASE)
    if priv_keys:
        results["private_keys"].append("Asymmetric Cryptographic Private Key header discovered")
        results["findings"].append({
            "type": "Private Key",
            "value": priv_keys[0],
            "redacted": "-----BEGIN PRIVATE KEY----- [REDACTED]",
            "severity": "CRITICAL",
        })

    # 7. Passwords in cleartext assignments
    pass_matches = re.findall(r"(?:password|passwd|pwd|secret|db_pass)\s*[:=]\s*['\"]?([^\s'\"]{6,})", text, re.IGNORECASE)
    for p in set(pass_matches):
        if not p.startswith("http") and len(p) < 40:
            results["passwords"].append(f"Hardcoded Password Assignment: {_redact_secret(p)}")
            results["findings"].append({
                "type": "Cleartext Password Assignment",
                "value": p,
                "redacted": _redact_secret(p),
                "severity": "HIGH",
            })

    # 8. Credit Card Numbers
    cc_candidates = re.findall(r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b", text)
    for cc in set(cc_candidates):
        clean_cc = re.sub(r"[ -]", "", cc)
        if _luhn_checksum(clean_cc):
            results["pii"].append(f"Credit Card Number: {_redact_secret(clean_cc)}")
            results["findings"].append({
                "type": "Payment Card (Luhn Verified)",
                "value": clean_cc,
                "redacted": _redact_secret(clean_cc),
                "severity": "CRITICAL",
            })

    # 9. National ID / SSN
    ssn_matches = re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text)
    for ssn in set(ssn_matches):
        results["pii"].append(f"US SSN: {_redact_secret(ssn)}")
        results["findings"].append({
            "type": "US Social Security Number",
            "value": ssn,
            "redacted": _redact_secret(ssn),
            "severity": "HIGH",
        })

    tc_candidates = re.findall(r"\b[1-9]\d{10}\b", text)
    for tc in set(tc_candidates):
        if _validate_tc_kimlik(tc):
            results["pii"].append(f"Turkish National ID (TC Kimlik): {_redact_secret(tc)}")
            results["findings"].append({
                "type": "Turkish National ID",
                "value": tc,
                "redacted": _redact_secret(tc),
                "severity": "HIGH",
            })

    # 10. BIP39 Seed Words Sequence
    words = re.findall(r"\b[a-z]{3,8}\b", text.lower())
    consecutive_bip39 = []
    current_seq = []
    for w in words:
        if w in BIP39_SAMPLE:
            current_seq.append(w)
        else:
            if len(current_seq) in (12, 18, 24):
                consecutive_bip39.append(current_seq)
            current_seq = []
    if len(current_seq) in (12, 18, 24):
        consecutive_bip39.append(current_seq)

    for seq in consecutive_bip39:
        joined_seq = " ".join(seq)
        results["private_keys"].append(f"BIP39 Crypto Seed Phrase ({len(seq)} words): {_redact_secret(joined_seq)}")
        results["findings"].append({
            "type": "Cryptocurrency Recovery Seed Phrase",
            "value": joined_seq,
            "redacted": _redact_secret(joined_seq),
            "severity": "CRITICAL",
        })

    return results


def analyze_ocr(pil_img: Optional[Image.Image], raw_text_fallback: str = "") -> OCRReport:
    """Analyze image using OCR and scan for confidential data leaks."""
    report = OCRReport()
    extracted_text, engine = _extract_text_heuristic(pil_img)

    # If OCR produced no text, use raw_text_fallback (from strings scan)
    combined_text = extracted_text or raw_text_fallback
    report.ocr_performed = True
    report.engine_used = engine if extracted_text else "Binary String Slicer"
    report.extracted_text = combined_text[:2000]
    report.character_count = len(combined_text)
    report.word_count = len(combined_text.split())
    report.text_detected = report.word_count >= 2

    # Run leak detector
    leak_data = scan_sensitive_leaks(combined_text)
    report.sensitive_findings = leak_data["findings"]
    report.api_keys_found = leak_data["api_keys"]
    report.passwords_found = leak_data["passwords"]
    report.tokens_found = leak_data["tokens"]
    report.pii_found = leak_data["pii"]
    report.private_keys_found = leak_data["private_keys"]

    for f in leak_data["findings"]:
        report.findings.append(f"Confidential Secret Leak [{f['type']}]: {f['redacted']} ({f['severity']}).")

    return report

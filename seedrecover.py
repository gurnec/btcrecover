#!/usr/bin/python

# seedrecover.py -- Bitcoin mnemonic sentence recovery tool
# Copyright (C) 2015 Christopher Gurnee
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License version 2 for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8
#
#                      Thank You!

# PYTHON_ARGCOMPLETE_OK - enables optional bash tab completion

# TODO: finish pythonizing comments/documentation

# (all futures as of 2.6 and 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division, \
                       generators, nested_scopes, with_statement

__version__ = "0.1.0"

import btcrecover as btcr, sys, os, base64, hashlib, difflib, itertools, atexit

# Try to add the Armory libraries to the path for various platforms
if sys.platform == "win32":
    win32_path = os.environ.get("ProgramFiles", r"C:\Program Files (x86)") + r"\Armory"
    sys.path.extend((win32_path, win32_path + r"\library.zip"))
elif sys.platform.startswith("linux"):
    sys.path.append("/usr/lib/armory")
elif sys.platform == "darwin":  # untested
    sys.path.append("/Applications/Armory.app/Contents/MacOS/py/usr/lib/armory")
#
from CppBlockUtils import CryptoECDSA, SecureBinaryData


# Order of the base point generator, from SEC 2
GENERATOR_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141L


################################### Utility Functions ###################################


def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to a long integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: long
    """
    return long(base64.b16encode(bytes_rep), 16)

def int_to_bytes(int_rep, min_length=0):
    """convert an unsigned integer to a string of bytes (in big-endian order)

    :param int_rep: a non-negative integer
    :type int_rep: long or int
    :param min_length: the minimum output length
    :type min_length: int
    :return: the raw bytes, zero-padded (at the beginning) if necessary
    :rtype: str
    """
    assert int_rep >= 0
    hex_rep = "{:X}".format(int_rep)
    if len(hex_rep) % 2 == 1:    # The hex decoder below requires
        hex_rep = "0" + hex_rep  # exactly 2 chars per byte.
    return base64.b16decode(hex_rep).rjust(min_length, "\0")


dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }

def base58check_to_hash160(base58_rep):
    """convert from a base58check address to its hash160 form

    :param base58_rep: check-code appended base58-encoded address
    :type base58_rep: str
    :return: ripemd160(sha256()) hash of the pubkey/redeemScript and the version byte
    :rtype: (str, str)
    """
    base58_stripped = base58_rep.lstrip("1")

    int_rep = 0
    for base58_digit in base58_stripped:
        int_rep *= 58
        int_rep += base58_digit_to_dec[base58_digit]

    # Convert int to raw bytes
    all_bytes  = int_to_bytes(int_rep, 1 + 20 + 4)

    zero_count = next(zeros for zeros,byte in enumerate(all_bytes) if byte != "\0")
    if len(base58_rep) - len(base58_stripped) != zero_count:
        raise ValueError("prepended zeros mismatch")

    version_byte, hash160_bytes, check_bytes = all_bytes[:1], all_bytes[1:-4], all_bytes[-4:]
    if hashlib.sha256(hashlib.sha256(version_byte + hash160_bytes).digest()).digest()[:4] != check_bytes:
        raise ValueError("base58 check code mismatch")

    return hash160_bytes, version_byte

def pubkey_to_hash160(pubkey_bytes):
    """convert from a raw public key to its a hash160 form

    :param pubkey_bytes: SEC 1 EllipticCurvePoint OctetString
    :type pubkey_bytes: str
    :return: ripemd160(sha256(pubkey_bytes))
    :rtype: str
    """
    assert len(pubkey_bytes) == 65 and pubkey_bytes[0] == "\x04" or \
           len(pubkey_bytes) == 33 and pubkey_bytes[0] in "\x00\x01"
    return hashlib.new("ripemd160", hashlib.sha256(pubkey_bytes).digest()).digest()


################################### Wallets ###################################
# TODO: implement other wallets; bitcoinj? Electrum 2? generic BIP39?

btcr.clear_registered_wallets()

############### Electrum1 ###############

@btcr.register_wallet_class  # enables wallet type auto-detection via is_wallet_file()
class WalletElectrum1(object):

    # This is the Electrum1 wordlist
    _words      = ( "like", "just", "love", "know", "never", "want", "time", "out", "there", "make", "look", "eye", "down", "only", "think", "heart", "back", "then", "into", "about", "more", "away", "still", "them", "take", "thing", "even", "through", "long", "always", "world", "too", "friend", "tell", "try", "hand", "thought", "over", "here", "other", "need", "smile", "again", "much", "cry", "been", "night", "ever", "little", "said", "end", "some", "those", "around", "mind", "people", "girl", "leave", "dream", "left", "turn", "myself", "give", "nothing", "really", "off", "before", "something", "find", "walk", "wish", "good", "once", "place", "ask", "stop", "keep", "watch", "seem", "everything", "wait", "got", "yet", "made", "remember", "start", "alone", "run", "hope", "maybe", "believe", "body", "hate", "after", "close", "talk", "stand", "own", "each", "hurt", "help", "home", "god", "soul", "new", "many", "two", "inside", "should", "true", "first", "fear", "mean", "better", "play", "another", "gone", "change", "use", "wonder", "someone", "hair", "cold", "open", "best", "any", "behind", "happen", "water", "dark", "laugh", "stay", "forever", "name", "work", "show", "sky", "break", "came", "deep", "door", "put", "black", "together", "upon", "happy", "such", "great", "white", "matter", "fill", "past", "please", "burn", "cause", "enough", "touch", "moment", "soon", "voice", "scream", "anything", "stare", "sound", "red", "everyone", "hide", "kiss", "truth", "death", "beautiful", "mine", "blood", "broken", "very", "pass", "next", "forget", "tree", "wrong", "air", "mother", "understand", "lip", "hit", "wall", "memory", "sleep", "free", "high", "realize", "school", "might", "skin", "sweet", "perfect", "blue", "kill", "breath", "dance", "against", "fly", "between", "grow", "strong", "under", "listen", "bring", "sometimes", "speak", "pull", "person", "become", "family", "begin", "ground", "real", "small", "father", "sure", "feet", "rest", "young", "finally", "land", "across", "today", "different", "guy", "line", "fire", "reason", "reach", "second", "slowly", "write", "eat", "smell", "mouth", "step", "learn", "three", "floor", "promise", "breathe", "darkness", "push", "earth", "guess", "save", "song", "above", "along", "both", "color", "house", "almost", "sorry", "anymore", "brother", "okay", "dear", "game", "fade", "already", "apart", "warm", "beauty", "heard", "notice", "question", "shine", "began", "piece", "whole", "shadow", "secret", "street", "within", "finger", "point", "morning", "whisper", "child", "moon", "green", "story", "glass", "kid", "silence", "since", "soft", "yourself", "empty", "shall", "angel", "answer", "baby", "bright", "dad", "path", "worry", "hour", "drop", "follow", "power", "war", "half", "flow", "heaven", "act", "chance", "fact", "least", "tired", "children", "near", "quite", "afraid", "rise", "sea", "taste", "window", "cover", "nice", "trust", "lot", "sad", "cool", "force", "peace", "return", "blind", "easy", "ready", "roll", "rose", "drive", "held", "music", "beneath", "hang", "mom", "paint", "emotion", "quiet", "clear", "cloud", "few", "pretty", "bird", "outside", "paper", "picture", "front", "rock", "simple", "anyone", "meant", "reality", "road", "sense", "waste", "bit", "leaf", "thank", "happiness", "meet", "men", "smoke", "truly", "decide", "self", "age", "book", "form", "alive", "carry", "escape", "damn", "instead", "able", "ice", "minute", "throw", "catch", "leg", "ring", "course", "goodbye", "lead", "poem", "sick", "corner", "desire", "known", "problem", "remind", "shoulder", "suppose", "toward", "wave", "drink", "jump", "woman", "pretend", "sister", "week", "human", "joy", "crack", "grey", "pray", "surprise", "dry", "knee", "less", "search", "bleed", "caught", "clean", "embrace", "future", "king", "son", "sorrow", "chest", "hug", "remain", "sat", "worth", "blow", "daddy", "final", "parent", "tight", "also", "create", "lonely", "safe", "cross", "dress", "evil", "silent", "bone", "fate", "perhaps", "anger", "class", "scar", "snow", "tiny", "tonight", "continue", "control", "dog", "edge", "mirror", "month", "suddenly", "comfort", "given", "loud", "quickly", "gaze", "plan", "rush", "stone", "town", "battle", "ignore", "spirit", "stood", "stupid", "yours", "brown", "build", "dust", "hey", "kept", "pay", "phone", "twist", "although", "ball", "beyond", "hidden", "nose", "taken", "fail", "float", "pure", "somehow", "wash", "wrap", "angry", "cheek", "creature", "forgotten", "heat", "rip", "single", "space", "special", "weak", "whatever", "yell", "anyway", "blame", "job", "choose", "country", "curse", "drift", "echo", "figure", "grew", "laughter", "neck", "suffer", "worse", "yeah", "disappear", "foot", "forward", "knife", "mess", "somewhere", "stomach", "storm", "beg", "idea", "lift", "offer", "breeze", "field", "five", "often", "simply", "stuck", "win", "allow", "confuse", "enjoy", "except", "flower", "seek", "strength", "calm", "grin", "gun", "heavy", "hill", "large", "ocean", "shoe", "sigh", "straight", "summer", "tongue", "accept", "crazy", "everyday", "exist", "grass", "mistake", "sent", "shut", "surround", "table", "ache", "brain", "destroy", "heal", "nature", "shout", "sign", "stain", "choice", "doubt", "glance", "glow", "mountain", "queen", "stranger", "throat", "tomorrow", "city", "either", "fish", "flame", "rather", "shape", "spin", "spread", "ash", "distance", "finish", "image", "imagine", "important", "nobody", "shatter", "warmth", "became", "feed", "flesh", "funny", "lust", "shirt", "trouble", "yellow", "attention", "bare", "bite", "money", "protect", "amaze", "appear", "born", "choke", "completely", "daughter", "fresh", "friendship", "gentle", "probably", "six", "deserve", "expect", "grab", "middle", "nightmare", "river", "thousand", "weight", "worst", "wound", "barely", "bottle", "cream", "regret", "relationship", "stick", "test", "crush", "endless", "fault", "itself", "rule", "spill", "art", "circle", "join", "kick", "mask", "master", "passion", "quick", "raise", "smooth", "unless", "wander", "actually", "broke", "chair", "deal", "favorite", "gift", "note", "number", "sweat", "box", "chill", "clothes", "lady", "mark", "park", "poor", "sadness", "tie", "animal", "belong", "brush", "consume", "dawn", "forest", "innocent", "pen", "pride", "stream", "thick", "clay", "complete", "count", "draw", "faith", "press", "silver", "struggle", "surface", "taught", "teach", "wet", "bless", "chase", "climb", "enter", "letter", "melt", "metal", "movie", "stretch", "swing", "vision", "wife", "beside", "crash", "forgot", "guide", "haunt", "joke", "knock", "plant", "pour", "prove", "reveal", "steal", "stuff", "trip", "wood", "wrist", "bother", "bottom", "crawl", "crowd", "fix", "forgive", "frown", "grace", "loose", "lucky", "party", "release", "surely", "survive", "teacher", "gently", "grip", "speed", "suicide", "travel", "treat", "vein", "written", "cage", "chain", "conversation", "date", "enemy", "however", "interest", "million", "page", "pink", "proud", "sway", "themselves", "winter", "church", "cruel", "cup", "demon", "experience", "freedom", "pair", "pop", "purpose", "respect", "shoot", "softly", "state", "strange", "bar", "birth", "curl", "dirt", "excuse", "lord", "lovely", "monster", "order", "pack", "pants", "pool", "scene", "seven", "shame", "slide", "ugly", "among", "blade", "blonde", "closet", "creek", "deny", "drug", "eternity", "gain", "grade", "handle", "key", "linger", "pale", "prepare", "swallow", "swim", "tremble", "wheel", "won", "cast", "cigarette", "claim", "college", "direction", "dirty", "gather", "ghost", "hundred", "loss", "lung", "orange", "present", "swear", "swirl", "twice", "wild", "bitter", "blanket", "doctor", "everywhere", "flash", "grown", "knowledge", "numb", "pressure", "radio", "repeat", "ruin", "spend", "unknown", "buy", "clock", "devil", "early", "false", "fantasy", "pound", "precious", "refuse", "sheet", "teeth", "welcome", "add", "ahead", "block", "bury", "caress", "content", "depth", "despite", "distant", "marry", "purple", "threw", "whenever", "bomb", "dull", "easily", "grasp", "hospital", "innocence", "normal", "receive", "reply", "rhyme", "shade", "someday", "sword", "toe", "visit", "asleep", "bought", "center", "consider", "flat", "hero", "history", "ink", "insane", "muscle", "mystery", "pocket", "reflection", "shove", "silently", "smart", "soldier", "spot", "stress", "train", "type", "view", "whether", "bus", "energy", "explain", "holy", "hunger", "inch", "magic", "mix", "noise", "nowhere", "prayer", "presence", "shock", "snap", "spider", "study", "thunder", "trail", "admit", "agree", "bag", "bang", "bound", "butterfly", "cute", "exactly", "explode", "familiar", "fold", "further", "pierce", "reflect", "scent", "selfish", "sharp", "sink", "spring", "stumble", "universe", "weep", "women", "wonderful", "action", "ancient", "attempt", "avoid", "birthday", "branch", "chocolate", "core", "depress", "drunk", "especially", "focus", "fruit", "honest", "match", "palm", "perfectly", "pillow", "pity", "poison", "roar", "shift", "slightly", "thump", "truck", "tune", "twenty", "unable", "wipe", "wrote", "coat", "constant", "dinner", "drove", "egg", "eternal", "flight", "flood", "frame", "freak", "gasp", "glad", "hollow", "motion", "peer", "plastic", "root", "screen", "season", "sting", "strike", "team", "unlike", "victim", "volume", "warn", "weird", "attack", "await", "awake", "built", "charm", "crave", "despair", "fought", "grant", "grief", "horse", "limit", "message", "ripple", "sanity", "scatter", "serve", "split", "string", "trick", "annoy", "blur", "boat", "brave", "clearly", "cling", "connect", "fist", "forth", "imagination", "iron", "jock", "judge", "lesson", "milk", "misery", "nail", "naked", "ourselves", "poet", "possible", "princess", "sail", "size", "snake", "society", "stroke", "torture", "toss", "trace", "wise", "bloom", "bullet", "cell", "check", "cost", "darling", "during", "footstep", "fragile", "hallway", "hardly", "horizon", "invisible", "journey", "midnight", "mud", "nod", "pause", "relax", "shiver", "sudden", "value", "youth", "abuse", "admire", "blink", "breast", "bruise", "constantly", "couple", "creep", "curve", "difference", "dumb", "emptiness", "gotta", "honor", "plain", "planet", "recall", "rub", "ship", "slam", "soar", "somebody", "tightly", "weather", "adore", "approach", "bond", "bread", "burst", "candle", "coffee", "cousin", "crime", "desert", "flutter", "frozen", "grand", "heel", "hello", "language", "level", "movement", "pleasure", "powerful", "random", "rhythm", "settle", "silly", "slap", "sort", "spoken", "steel", "threaten", "tumble", "upset", "aside", "awkward", "bee", "blank", "board", "button", "card", "carefully", "complain", "crap", "deeply", "discover", "drag", "dread", "effort", "entire", "fairy", "giant", "gotten", "greet", "illusion", "jeans", "leap", "liquid", "march", "mend", "nervous", "nine", "replace", "rope", "spine", "stole", "terror", "accident", "apple", "balance", "boom", "childhood", "collect", "demand", "depression", "eventually", "faint", "glare", "goal", "group", "honey", "kitchen", "laid", "limb", "machine", "mere", "mold", "murder", "nerve", "painful", "poetry", "prince", "rabbit", "shelter", "shore", "shower", "soothe", "stair", "steady", "sunlight", "tangle", "tease", "treasure", "uncle", "begun", "bliss", "canvas", "cheer", "claw", "clutch", "commit", "crimson", "crystal", "delight", "doll", "existence", "express", "fog", "football", "gay", "goose", "guard", "hatred", "illuminate", "mass", "math", "mourn", "rich", "rough", "skip", "stir", "student", "style", "support", "thorn", "tough", "yard", "yearn", "yesterday", "advice", "appreciate", "autumn", "bank", "beam", "bowl", "capture", "carve", "collapse", "confusion", "creation", "dove", "feather", "girlfriend", "glory", "government", "harsh", "hop", "inner", "loser", "moonlight", "neighbor", "neither", "peach", "pig", "praise", "screw", "shield", "shimmer", "sneak", "stab", "subject", "throughout", "thrown", "tower", "twirl", "wow", "army", "arrive", "bathroom", "bump", "cease", "cookie", "couch", "courage", "dim", "guilt", "howl", "hum", "husband", "insult", "led", "lunch", "mock", "mostly", "natural", "nearly", "needle", "nerd", "peaceful", "perfection", "pile", "price", "remove", "roam", "sanctuary", "serious", "shiny", "shook", "sob", "stolen", "tap", "vain", "void", "warrior", "wrinkle", "affection", "apologize", "blossom", "bounce", "bridge", "cheap", "crumble", "decision", "descend", "desperately", "dig", "dot", "flip", "frighten", "heartbeat", "huge", "lazy", "lick", "odd", "opinion", "process", "puzzle", "quietly", "retreat", "score", "sentence", "separate", "situation", "skill", "soak", "square", "stray", "taint", "task", "tide", "underneath", "veil", "whistle", "anywhere", "bedroom", "bid", "bloody", "burden", "careful", "compare", "concern", "curtain", "decay", "defeat", "describe", "double", "dreamer", "driver", "dwell", "evening", "flare", "flicker", "grandma", "guitar", "harm", "horrible", "hungry", "indeed", "lace", "melody", "monkey", "nation", "object", "obviously", "rainbow", "salt", "scratch", "shown", "shy", "stage", "stun", "third", "tickle", "useless", "weakness", "worship", "worthless", "afternoon", "beard", "boyfriend", "bubble", "busy", "certain", "chin", "concrete", "desk", "diamond", "doom", "drawn", "due", "felicity", "freeze", "frost", "garden", "glide", "harmony", "hopefully", "hunt", "jealous", "lightning", "mama", "mercy", "peel", "physical", "position", "pulse", "punch", "quit", "rant", "respond", "salty", "sane", "satisfy", "savior", "sheep", "slept", "social", "sport", "tuck", "utter", "valley", "wolf", "aim", "alas", "alter", "arrow", "awaken", "beaten", "belief", "brand", "ceiling", "cheese", "clue", "confidence", "connection", "daily", "disguise", "eager", "erase", "essence", "everytime", "expression", "fan", "flag", "flirt", "foul", "fur", "giggle", "glorious", "ignorance", "law", "lifeless", "measure", "mighty", "muse", "north", "opposite", "paradise", "patience", "patient", "pencil", "petal", "plate", "ponder", "possibly", "practice", "slice", "spell", "stock", "strife", "strip", "suffocate", "suit", "tender", "tool", "trade", "velvet", "verse", "waist", "witch", "aunt", "bench", "bold", "cap", "certainly", "click", "companion", "creator", "dart", "delicate", "determine", "dish", "dragon", "drama", "drum", "dude", "everybody", "feast", "forehead", "former", "fright", "fully", "gas", "hook", "hurl", "invite", "juice", "manage", "moral", "possess", "raw", "rebel", "royal", "scale", "scary", "several", "slight", "stubborn", "swell", "talent", "tea", "terrible", "thread", "torment", "trickle", "usually", "vast", "violence", "weave", "acid", "agony", "ashamed", "awe", "belly", "blend", "blush", "character", "cheat", "common", "company", "coward", "creak", "danger", "deadly", "defense", "define", "depend", "desperate", "destination", "dew", "duck", "dusty", "embarrass", "engine", "example", "explore", "foe", "freely", "frustrate", "generation", "glove", "guilty", "health", "hurry", "idiot", "impossible", "inhale", "jaw", "kingdom", "mention", "mist", "moan", "mumble", "mutter", "observe", "ode", "pathetic", "pattern", "pie", "prefer", "puff", "rape", "rare", "revenge", "rude", "scrape", "spiral", "squeeze", "strain", "sunset", "suspend", "sympathy", "thigh", "throne", "total", "unseen", "weapon", "weary" )
    _word_to_id = { word:id for id,word in enumerate(_words) }

    @property
    def word_ids(self):        return xrange(len(self.__class__._words))
    @classmethod
    def id_to_word(cls, id):   return cls._words[id]
    @classmethod
    def word_to_id(cls, word): return cls._word_to_id[word]

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no"
        return None if wallet_file.read(2) == b"{'" else False

    def __init__(self, loading = False):
        assert loading, "use load_from_filename or create_from_params to create a " + self.__class__.__name__
        self._master_pubkey   = None

    def __getstate__(self):
        # Convert unpicklable Armory library object to a standard binary string
        state = self.__dict__.copy()
        if self._master_pubkey:
            state["_master_pubkey"] = self._master_pubkey.toBinStr()
        return state

    def __setstate__(self, state):
        # Restore unpicklable Armory library object
        if state["_master_pubkey"]:
            state["_master_pubkey"] = SecureBinaryData(state["_master_pubkey"])
        self.__dict__ = state

    @staticmethod
    def passwords_per_seconds(seconds):
        return max(int(round(8 * seconds)), 1)

    # Load an Electrum1 wallet file (the part of it we need, just the master public key)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        from ast import literal_eval
        with open(wallet_filename) as wallet_file:
            wallet = literal_eval(wallet_file.read(1048576))  # up to 1M, typical size is a few k
        seed_version = wallet.get("seed_version")
        if seed_version is None:             raise ValueError("Unrecognized wallet format (Electrum1 seed_version not found)")
        if seed_version != 4:                raise NotImplementedError("Unsupported Electrum1 seed version " + seed_version)
        if not wallet.get("use_encryption"): raise ValueError("Electrum1 wallet is not encrypted")
        master_pubkey = base64.b16decode(wallet["master_public_key"], casefold=True)
        if len(master_pubkey) != 64:         raise ValueError("Electrum1 master public key is not 64 bytes long")
        self = cls(loading=True)
        self._master_pubkey = SecureBinaryData("\x04" + master_pubkey)  # prepend the uncompressed tag
        return self

    # Creates a wallet instance from either an mpk or an address and address_limit.
    # If neither an mpk nor address is supplied, prompts the user for one or the other.
    @classmethod
    def create_from_params(cls, mpk=None, address=None, address_limit=None):
        self = cls(loading=True)

        # Process the mpk (master public key) argument
        if mpk:
            mpk = base64.b16decode(mpk, casefold=True)
            # (it's assigned to the self._master_pubkey later)

        # Process the address argument
        if address:
            if mpk:
                print("address is ignored when an mpk is provided", file=sys.stderr)
            else:
                assert address_limit and address_limit > 0, "a positive address-limit is required when an address is provided"
                self._known_hash160, version_byte = base58check_to_hash160(address)
                self._addrs_to_generate = address_limit
                assert version_byte == "\0", "Electrum1 only supports P2PKH addresses"

        # If neither mpk nor address arguments were provided, prompt the user for an mpk first
        if not mpk and not address:
            init_gui()
            while True:
                mpk = tkSimpleDialog.askstring("Master public key",
                    "Please enter your master public key if you have it, or click Cancel to search by an address instead:")
                if not mpk:
                    break  # if they pressed Cancel, stop prompting for an mpk
                mpk = mpk.strip()
                try:
                    if len(mpk) != 128:
                        raise TypeError()
                    mpk = base64.b16decode(mpk, casefold=True)  # raises TypeError() on failure
                    break
                except TypeError:
                    tkMessageBox.showerror("Master public key", "The entered key is not exactly 128 hex digits long")

        # If an mpk has been provided (in the function call or from a user), convert it to the needed format
        if mpk:
            assert len(mpk) == 64, "mpk is 64 bytes long (after decoding from hex)"
            self._master_pubkey = SecureBinaryData("\x04" + mpk)  # prepend the uncompressed tag

        # If an mpk wasn't provided (at all), and an address also wasn't provided
        # (in the original function call), prompt the user for an address.
        if not mpk and not address:
            while True:
                address = tkSimpleDialog.askstring("Bitcoin address",
                    "Please enter an address from your wallet, preferably one created early in your wallet's lifetime:")
                if not address:
                    sys.exit("canceled")
                address = address.strip()
                try:
                    # (raises ValueError() on failure):
                    self._known_hash160, version_byte = base58check_to_hash160(address)
                    if ord(version_byte) != 0:
                        raise ValueError("not a Bitcoin P2PKH address; version byte is {:#04x}".format(ord(version_byte)))
                    break
                except ValueError as e:
                    tkMessageBox.showerror("Bitcoin address", "The entered address is invalid ({})".format(e))

            self._addrs_to_generate = tkSimpleDialog.askinteger("Address limit",
                "Please enter the address generation limit. Smaller is faster, but it should be\n"
                "larger than the number of addresses created before the one you just entered:", minvalue=1)
            if not self._addrs_to_generate:
                sys.exit("canceled")

        return self

    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        return len(mnemonic_ids) == 12 and None not in mnemonic_ids

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def return_verified_password_or_false(self, mnemonic_ids_list):
        # Copy some vars into local for a small speed boost
        l_sha256     = hashlib.sha256
        num_words    = len(self.__class__._words)
        num_words2   = num_words * num_words
        crypto_ecdsa = CryptoECDSA()

        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):
            # Compute the binary seed from the word list the Electrum1 way
            seed = ""
            for i in xrange(0, 12, 3):
                seed += "{:08x}".format( mnemonic_ids[i    ]
                     + num_words  * (   (mnemonic_ids[i + 1] - mnemonic_ids[i    ]) % num_words )
                     + num_words2 * (   (mnemonic_ids[i + 2] - mnemonic_ids[i + 1]) % num_words ))
            #
            unstretched_seed = seed
            for i in xrange(100000):  # Electrum1's seed stretching
                seed = l_sha256(seed + unstretched_seed).digest()

            # If a master public key was provided, check the pubkey derived from the seed against it
            if self._master_pubkey:
                if crypto_ecdsa.CheckPubPrivKeyMatch(SecureBinaryData(seed), self._master_pubkey):
                    return mnemonic_ids, count  # found it

            # Else derive addrs_to_generate addresses from the seed, searching for a match with known_hash160
            else:
                master_privkey = bytes_to_int(seed)

                master_pubkey_bytes = crypto_ecdsa.ComputePublicKey(SecureBinaryData(seed)).toBinStr()
                assert master_pubkey_bytes[0] == "\x04", "ComputePublicKey() returns an uncompressed pubkey"
                master_pubkey_bytes = master_pubkey_bytes[1:]  # remove the uncompressed tag byte

                for seq_num in xrange(self._addrs_to_generate):
                    # Compute the next deterministic private/public key pair the Electrum1 way.
                    # FYI we derive a privkey first, and then a pubkey from that because it's
                    # likely faster than deriving a pubkey directly from the base point and
                    # seed -- it means doing a simple modular addition instead of a point
                    # addition (plus a scalar point multiplication which is needed for both).
                    d_offset  = bytes_to_int( l_sha256(l_sha256(
                            "{}:0:{}".format(seq_num, master_pubkey_bytes)  # 0 means: not a change address
                        ).digest()).digest() )
                    d_privkey = int_to_bytes((master_privkey + d_offset) % GENERATOR_ORDER, 32)

                    d_pubkey  = crypto_ecdsa.ComputePublicKey(SecureBinaryData(d_privkey))

                    if pubkey_to_hash160(d_pubkey.toBinStr()) == self._known_hash160:  # assumes uncompressed
                        return mnemonic_ids, count  # found it

        return False, count

    # Configures the values of four globals used later in config_btcrecover():
    # mnemonic_ids_guess, close_mnemonic_ids, num_inserts, and num_deletes
    @classmethod
    def config_mnemonic(cls, mnemonic_guess = None):
        # If a mnemonic guess wasn't provided, prompt the user for one
        if not mnemonic_guess:
            init_gui()
            mnemonic_guess = tkSimpleDialog.askstring("Electrum seed",
                "Please enter your best guess for your Electrum seed:")
            if not mnemonic_guess:
                sys.exit("canceled")

        # Convert the mnemonic words into numeric ids and pre-calculate similar mnemonic words
        global mnemonic_ids_guess, close_mnemonic_ids
        mnemonic_ids_guess = ()
        # close_mnemonic_ids is a dict; each dict key is a mnemonic_id (int), and each
        # dict value is a tuple containing length 1 tuples, and finally each of the
        # length 1 tuples contains a single mnemonic_id which is similar to the dict's key
        close_mnemonic_ids = {}
        for word in mnemonic_guess.lower().split():
            close_words = difflib.get_close_matches(word, cls._words, sys.maxint, 0.65)
            if close_words:
                if close_words[0] != word:
                    print("'{}' was in your guess, but it's not a valid Electrum seed word;\n"
                          "    trying '{}' instead.".format(word, close_words[0]))
                mnemonic_ids_guess += cls.word_to_id(close_words[0]),
                close_mnemonic_ids[mnemonic_ids_guess[-1]] = tuple( (cls.word_to_id(w),) for w in close_words[1:] )
            else:
                print("'{}' was in your guess, but there is no similar Electrum seed word;\n"
                      "    trying all possible seed words here instead.".format(word))
                mnemonic_ids_guess += None,

        global num_inserts, num_deletes
        num_inserts = max(12 - len(mnemonic_ids_guess), 0)
        num_deletes = max(len(mnemonic_ids_guess) - 12, 0)
        if num_inserts:
            print("Seed sentence was too short, inserting {} word{} into each guess."
                  .format(num_inserts, "s" if num_inserts > 1 else ""))
        if num_deletes:
            print("Seed sentence was too long, deleting {} word{} from each guess."
                  .format(num_deletes, "s" if num_deletes > 1 else ""))

    # Produces an infinite stream of differing mnemonic_ids guesses (for testing)
    @staticmethod
    def performance_iterator():
        return itertools.product(xrange(len(WalletElectrum1._words)), repeat = 12)


################################### Main ###################################


gui_initialized = False
def init_gui():
    global gui_initialized, tkFileDialog, tkSimpleDialog, tkMessageBox
    if not gui_initialized:
        import Tkinter, tkFileDialog, tkSimpleDialog, tkMessageBox
        Tkinter.Tk().withdraw()  # initialize library but don't display a window
        gui_initialized = True


# seedrecover.py uses routines from btcrecover.py to generate guesses, however
# instead of dealing with passwords (immutable sequences of characters), it deals
# with seeds (represented as immutable sequences of mnemonic_ids). More specifically,
# seeds are tuples of mnemonic_ids, and a mnemonic_id is just an int for Electrum1.

# These are simple typo generators; see btcrecover.py for additional information.
# Instead of returning iterables of sequences of characters (iterables of strings),
# these return iterables of sequences of mnemonic_ids (iterables of partial seeds).
#
@btcr.register_simple_typo("deleteword")
def delete_word(mnemonic_ids, i):
    return (),
#
@btcr.register_simple_typo("replaceword")
def replace_word(mnemonic_ids, i):
    if mnemonic_ids[i] is None: return (),      # don't touch invalid words
    return ((new_id,) for new_id in loaded_wallet.word_ids if new_id != mnemonic_ids[i])
#
@btcr.register_simple_typo("replacecloseword")
def replace_close_word(mnemonic_ids, i):
    if mnemonic_ids[i] is None: return (),      # don't touch invalid words
    return close_mnemonic_ids[mnemonic_ids[i]]  # the pre-calculated similar words
#
@btcr.register_simple_typo("replacewrongword")
def replace_wrong_word(mnemonic_ids, i):
    if mnemonic_ids[i] is not None: return (),  # only replace invalid words
    return ((new_id,) for new_id in loaded_wallet.word_ids)


# Builds a command line and then calls btcr.parse_arguments() with it.
#   typos     - max number of mistakes to apply to each guess
#   big_typos - max number of "big" mistakes to apply to each guess;
#               a big mistake involves replacing or inserting a word using the
#               full word list, and significantly increases the search time
#   min_typos - min number of typos to apply to each guess
num_inserts = num_deletes = 0
def config_btcrecover(typos, big_typos=0, min_typos=0):
    assert typos >= big_typos, "typos includes big_typos, therefore it must be >= big_typos"

    btcr_args = "--typos " + str(typos)

    # First, check if there are any required typos (if there are missing or extra
    # words in the guess) and adjust the max number of other typos to later apply

    any_typos  = typos  # the max number of typos left after removing required typos
    #big_typos =        # the max number of "big" typos after removing required typos (from args)

    if num_deletes:  # if the guess is too long (extra words need to be deleted)
        any_typos -= num_deletes
        btcr_args += " --typos-deleteword"
        if num_deletes < typos:
            btcr_args += " --max-typos-deleteword " + str(num_deletes)

    if num_inserts:  # if the guess is too short (words need to be inserted)
        any_typos -= num_inserts
        big_typos -= num_inserts
        # (don't need --typos-insert because we're using the inserted_items argument below)
        btcr_args += " --max-adjacent-inserts " + str(num_inserts)
        if num_inserts < typos:
            btcr_args += " --max-typos-insert " + str(num_inserts)

    num_wrong = sum(map(lambda id: id is None, mnemonic_ids_guess))
    if num_wrong:    # if any of the words were invalid (and need to be replaced)
        any_typos -= num_wrong
        big_typos -= num_wrong
        btcr_args += " --typos-replacewrongword"
        if num_wrong < typos:
            btcr_args += " --max-typos-replacewrongword " + str(num_wrong)

    if any_typos < 0:  # if too many typos are required to generate valid mnemonics
        print("Not enough mistakes permitted to produce a valid seed; skipping this phase.")
        return False

    if big_typos < 0:  # if too many big typos are required to generate valid mnemonics
        print("Not enough entirely different seed words permitted; skipping this phase.")
        return False

    # Because btcrecover doesn't support --min-typos-* on a per-typo basis, it ends
    # up generating some invalid guesses. We can use --min-typos to filter out some
    # of them (the remainder is later filtered out by verify_mnemonic_syntax()).
    min_typos = max(min_typos, num_inserts + num_deletes + num_wrong)
    if min_typos:
        btcr_args += " --min-typos " + str(min_typos)

    # Next, if the required typos above haven't consumed all available typos
    # (as specified by the function's args), add some "optional" typos

    if any_typos:
        btcr_args += " --typos-swap"
        if any_typos < typos:
            btcr_args += " --max-typos-swap " + str(any_typos)

        if big_typos:  # if there are any big typos left, add the replaceword typo
            btcr_args += " --typos-replaceword"
            if big_typos < typos:
                btcr_args += " --max-typos-replaceword " + str(big_typos)

        # only add replacecloseword typos if they're not
        # already covered by the replaceword typos added above
        num_replacecloseword = any_typos - big_typos
        if num_replacecloseword > 0:
            btcr_args += " --typos-replacecloseword"
            if num_replacecloseword < typos:
                btcr_args += " --max-typos-replacecloseword " + str(num_replacecloseword)

    btcr.parse_arguments(
        btcr_args.split(),
        inserted_items= ((id,) for id in loaded_wallet.word_ids) if num_inserts else None,
        wallet=         loaded_wallet,
        base_iterator=  (mnemonic_ids_guess,),
        perf_iterator=  loaded_wallet.performance_iterator,
        check_only=     loaded_wallet.verify_mnemonic_syntax
    )

    return True


loaded_wallet = None
if __name__ == b"__main__":

    if len(sys.argv) > 1:
        # TODO: command-line version
        raise NotImplementedError("command-line arguments not implemented")

    else:
        atexit.register(lambda: raw_input("\nPress Enter to exit ..."))
        init_gui()
        wallet_filename = tkFileDialog.askopenfilename(title="Please select your wallet file if you have one")
        if wallet_filename:
            loaded_wallet = btcr.load_wallet(wallet_filename)  # raises on failure; no second chance
        else:
            # TODO: wallet type selection dialog (Electrum 1 or bitcoinj or ...?)
            wallet_type   = WalletElectrum1
            loaded_wallet = wallet_type.create_from_params()  # user will be prompted for params
        mnemonic_guess = None  # user will be prompted for a seed guess

        # This is a good default for Electrum1 wallets (which are pretty slow to search)
        phases = dict(typos=2), dict(typos=1, big_typos=1), dict(typos=2, big_typos=1, min_typos=2)

    loaded_wallet.config_mnemonic(mnemonic_guess)
    for phase_num, phase_params in enumerate(phases, 1):

        # Print a friendly message describing this phase's search settings
        print("Phase {}/{}: ".format(phase_num, len(phases)), end='')
        if phase_params['typos'] == 1:
            print("1 mistake", end='')
        else:
            print("up to {} mistakes".format(phase_params['typos']), end='')
        if phase_params.get('big_typos'):
            if phase_params['big_typos'] == phase_params['typos'] == 1:
                print(" which can be an entirely different seed word.")
            else:
                print(", {} of which can be an entirely different seed word.".format(phase_params['big_typos']))
        else:
            print(", excluding entirely different seed words.")

        # Perform this phase's search
        if config_btcrecover(**phase_params):
            (mnemonic_found, not_found_msg) = btcr.main()

            if mnemonic_found:
                print("Seed found:", " ".join(loaded_wallet.id_to_word(i) for i in mnemonic_found))
                break
            elif not_found_msg:
                print("Seed not found" + (", sorry..." if phase_num==len(phases) else ""))
            else:
                exit(1)  # An error or Ctrl-C

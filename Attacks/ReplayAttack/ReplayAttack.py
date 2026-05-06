import time
import hmac
import json
import uuid
import hashlib
from typing import Dict, Set

SHARED_SECRET = b"super-secret-key"
ALLOWED_CLOCK_SKEW = 30  # seconds


class ReplayProtectedServer:
    def __init__(self) -> None:
        self.seen_nonces: Set[str] = set()

    def verify_request(self, packet: Dict[str, str]) -> bool:
        try:
            message = packet["message"]
            nonce = packet["nonce"]
            timestamp = int(packet["timestamp"])
            signature = packet["signature"]
        except KeyError:
            return False

        now = int(time.time())

        # Reject old or far-future packets
        if abs(now - timestamp) > ALLOWED_CLOCK_SKEW:
            print("Rejected: timestamp outside allowed window")
            return False

        # Reject reused nonces
        if nonce in self.seen_nonces:
            print("Rejected: replay detected (nonce already used)")
            return False

        expected_sig = sign_message(message, nonce, timestamp)

        if not hmac.compare_digest(signature, expected_sig):
            print("Rejected: invalid signature")
            return False

        self.seen_nonces.add(nonce)
        print("Accepted")
        return True


def sign_message(message: str, nonce: str, timestamp: int) -> str:
    payload = json.dumps(
        {"message": message, "nonce": nonce, "timestamp": timestamp},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    return hmac.new(SHARED_SECRET, payload, hashlib.sha256).hexdigest()


def make_client_packet(message: str) -> Dict[str, str]:
    nonce = str(uuid.uuid4())
    timestamp = int(time.time())
    signature = sign_message(message, nonce, timestamp)

    return {
        "message": message,
        "nonce": nonce,
        "timestamp": str(timestamp),
        "signature": signature,
    }


if __name__ == "__main__":
    server = ReplayProtectedServer()

    packet = make_client_packet("transfer=10")

    print("First send:")
    server.verify_request(packet)

    print("\nReplay of same packet:")
    server.verify_request(packet)
import time
import sys
import random

def show_attack_animation(target_ip, target_port, attack_type, duration=60):
    print(f"[*] Sending {attack_type} flood to {target_ip}:{target_port} for {duration}s")
    elapsed = 0
    while elapsed < duration:
        bar_len = 30
        filled = int((elapsed / duration) * bar_len)
        bar = "=" * filled + "-" * (bar_len - filled)
        sys.stdout.write(f"\r[*] [{bar}] {elapsed}/{duration}s")
        sys.stdout.flush()
        time.sleep(1)
        elapsed += 1
    sys.stdout.write(f"\r[*] [{'=' * bar_len}] {duration}/{duration}s - Done\n")
    sys.stdout.flush()
    return True

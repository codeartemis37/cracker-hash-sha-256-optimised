import asyncio
import hashlib
import string
import itertools
from tqdm import tqdm
from functools import lru_cache
import json
import os
import time

SAVE_FILE = "crack_progress.json"
SAVE_INTERVAL = 10  # Intervalle de sauvegarde en secondes
WORDLIST_FILE = "wordlist.txt"
NUM_WORKERS = 100  # Nombre de workers parallèles
QUEUE_SIZE = 1000  # Taille de la queue de mots de passe

@lru_cache(maxsize=1000000)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def try_password(target_hash, password):
    password_hash = hash_password(password)
    return password if password_hash == target_hash else None

def generate_passwords(max_length, start_from=""):
    chars = string.ascii_lowercase + string.digits
    start_length = len(start_from) if start_from else 1
    for length in range(start_length, max_length + 1):
        for password in itertools.product(chars, repeat=length):
            current = ''.join(password)
            if current > start_from:
                yield current

def save_progress(current_password, mode):
    with open(SAVE_FILE, "w") as f:
        json.dump({"last_password": current_password, "mode": mode}, f)

def load_progress():
    if os.path.exists(SAVE_FILE):
        with open(SAVE_FILE, "r") as f:
            data = json.load(f)
        return data.get("last_password", ""), data.get("mode", "wordlist")
    return "", "wordlist"

def read_wordlist():
    if os.path.exists(WORDLIST_FILE):
        with open(WORDLIST_FILE, "r") as f:
            return [line.strip() for line in f]
    return []

async def password_worker(worker_id, target_hash, password_queue, result_queue, progress_bar):
    while True:
        try:
            password = await password_queue.get()
            if password is None:
                break
            result = try_password(target_hash, password)
            progress_bar.update(1)
            if result:
                await result_queue.put(result)
                return
        except asyncio.CancelledError:
            break
        finally:
            password_queue.task_done()

async def bruteforce_sha256(target_hash, max_length=8):
    start_time = time.time()
    start_password, start_mode = load_progress()
    wordlist = read_wordlist()
    
    total_passwords = len(wordlist) + sum(len(string.ascii_lowercase + string.digits) ** i for i in range(1, max_length + 1))
    progress_bar = tqdm(total=total_passwords, desc="Progression", unit="mot", initial=0)

    passwords_tested = 0
    last_save_time = time.time()

    password_queue = asyncio.Queue(maxsize=QUEUE_SIZE)
    result_queue = asyncio.Queue()

    workers = [asyncio.create_task(password_worker(i, target_hash, password_queue, result_queue, progress_bar)) 
               for i in range(NUM_WORKERS)]

    async def feed_passwords():
        nonlocal passwords_tested, last_save_time
        mode = start_mode
        
        try:
            # Test wordlist
            if mode == "wordlist":
                for password in wordlist:
                    await password_queue.put(password)
                    passwords_tested += 1
                    if not result_queue.empty():
                        return

                mode = "bruteforce"
                save_progress("", mode)

            # Bruteforce
            password_generator = generate_passwords(max_length, start_password)
            for password in password_generator:
                await password_queue.put(password)
                passwords_tested += 1
                
                current_time = time.time()
                if current_time - last_save_time >= SAVE_INTERVAL:
                    save_progress(password, "bruteforce")
                    last_save_time = current_time
                
                if not result_queue.empty():
                    return
        finally:
            # Signal workers to stop
            for _ in range(NUM_WORKERS):
                await password_queue.put(None)

    feeder = asyncio.create_task(feed_passwords())

    try:
        done, pending = await asyncio.wait([feeder] + workers, return_when=asyncio.FIRST_COMPLETED)
        
        if not result_queue.empty():
            result = await result_queue.get()
            end_time = time.time()
            return result, end_time - start_time, passwords_tested
    finally:
        feeder.cancel()
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        progress_bar.close()

    end_time = time.time()
    return None, end_time - start_time, passwords_tested

async def main():
    target_hash = "8d4e931ea8f6969639c27edf0631c86a45c5961e64897f7207563271b8bdb92e"
    
    try:
        result, elapsed_time, passwords_tested = await bruteforce_sha256(target_hash, max_length=8)
        if result:
            print(f"\nMot de passe trouvé : {result}")
        else:
            print("\nMot de passe non trouvé")
        print(f"Temps écoulé : {elapsed_time:.2f} secondes")
        print(f"Nombre de mots de passe testés : {passwords_tested}")
    except KeyboardInterrupt:
        print("\nInterruption détectée. Sauvegarde du progrès...")
    except asyncio.CancelledError:
        print("\nTâche annulée. Sauvegarde du progrès effectuée.")
    
    while True: 
        input("Vous pouvez fermer cette fenêtre")

if __name__ == "__main__":
    asyncio.run(main())

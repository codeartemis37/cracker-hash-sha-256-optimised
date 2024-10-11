import hashlib
import string
import itertools
from tqdm import tqdm
import time

SAVE_FILE = "crack_progress.json"
SAVE_INTERVAL = 10  # Intervalle de sauvegarde en secondes
WORDLIST_FILE = "wordlist.txt"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_passwords(max_length, charset):
    for length in range(1, max_length + 1):
        for p in itertools.product(charset, repeat=length):
            yield ''.join(p)

def bruteforce_sha256(target_hash, max_length=8, charset=string.ascii_lowercase + string.digits):
    start_time = time.time()
    
    total_passwords = sum(len(charset) ** i for i in range(1, max_length + 1))
    progress_bar = tqdm(total=total_passwords, desc="Progression", unit="mot")

    password_generator = generate_passwords(max_length, charset)

    for password in password_generator:
        if hash_password(password) == target_hash:
            end_time = time.time()
            progress_bar.close()
            return password, end_time - start_time
        
        progress_bar.update(1)

    progress_bar.close()
    end_time = time.time()
    return None, end_time - start_time

def main():
    target_hash = "8d4e931ea8f6969639c27edf0631c86a45c5961e64897f7207563271b8bdb92e"
    max_length = 6
    charset = string.ascii_lowercase + string.digits
    
    print(f"Recherche du mot de passe pour le hash : {target_hash}")
    print(f"Longueur maximale : {max_length}")
    print(f"Jeu de caractères : {charset}")
    
    result, elapsed_time = bruteforce_sha256(target_hash, max_length, charset)
    
    if result:
        print(f"\nMot de passe trouvé : {result}")
    else:
        print("\nMot de passe non trouvé")
    
    print(f"Temps écoulé : {elapsed_time:.2f} secondes")

if __name__ == "__main__":
    main()

# Project 2: Cryptography — Written Answers

---

## Part 1: Symmetric Encryption

### 1.1 Encrypt and Decrypt a File

-pdkdf2 takes a word/sentence and scrables it up thousands of times using a hashing function iterations/stretching and puts it into a string of numbers and letters. Encrypting a passphrase requires it because using the encryption stretching the key to the certain size needed 256 bits and it slows down an attacker trying to bruteforce a password of yours.

### 1.2 Encrypt the Same File Twice

**Why the checksums are different:**

everytime openssl encrypts it generates a unique new encryption no matter if the sentence its encrypting is identical or not. It ensures the openssl ciphertext is unique every run.

**What would be wrong with an encryption scheme where the two encrypted files were identical:**

If the ciphertext was always the same an attacker could just compare content in files and see that they're identical without ever breaking the encryption the attacker would know its the same message. If ur text is very simple and the attacker already knows it they'd be able to see that all ur file contents are the same

### 1.3 Watching ECB Leak Information

**1. How many distinct blocks does each encryption produce, and how many times does the most common ECB block repeat?**

ECB produced 3 distinct blocks. The most common block repeating 24 times the a block and the b block repeating 12 times and 1 unique block. WHile CBC produced 37 unique blocks.

**2. What exactly did ECB leak? To an attacker who never learns your key, what information is that worth?**

ECB leaked the structure of the text - specifically the file the contains the two repeating patterns with the a block appearing much more than the b. A attacker would be able to see that theres only three sections and that the first and third are the same while the second is differnet. This alone could reveal identical transactions, and repeated used databases.

**3. What is one question you would ask before believing the records are protected?**

For my question I would ask if every input for the encryption has a unique value or if its reused.

---

## Part 2: Integrity

### 2.2 Keyed Hashing

**1. Why the SHA-256 hash does not protect your colleague:**

SHA-256 is only just a hash function with no secret component. If an attacker were to get in and control ur path they would be able to modify it, compute a new hash of the file, and send it back to you as their modified file like eve in the middle.

**2. What changes when you use an HMAC instead:**

HMAC mixes that shared key into the hashing process so when my colleague gets the file and HMAC they are able to recompute the HMAC using the secret key we have shared. If an attacker were to modify this file they wouldnt be able to create a valid HMAC without knowing our secret key.

**3. What the attacker can and cannot do in each situation (SHA-256 and HMAC):**

An attacker can modify, compute another hash, and trick our colleague but our attacker would be detected if the channel the hash was sent through was protected. With HMAC the attacker can modify, and delete the message but cannot create a HMAC or trick our colleague.

---

## Part 3: Cryptographic Keys

### Written Answers

**1. What does the keyserver's email verification check prove? What does it not prove?**

This proves that whoever uploaded the key has access to the email its linked to in that moment, so just a proof of ownership. It doesnt prove if your the actual person who made the key, if its trustworthy, anything within the key, and its not 100% secure if ur email is compromised.

**2. Procedure for checking that a classmate's key really belongs to them, and why it works:**

For checking a classmates key I would first download the key and write down the fingerprint, then talk to that specific classmate in before or after lecture and have them read off their key from their laptop and compare it to the one I have written down. This works because A I know who made the key and they're telling me their fingerprint leaving no room for someone to intercept it or change it up on me. I have the original creator telling me themselves.

---

## Part 4: Asymmetric Encryption in Use

### 4.2 Find the Hybrid Encryption

**1. What is contained in each packet?**

Each packet has a random generated session key encrypted with my public key. It doesnt have anything to do with my message its just the key that would be used to decrpyt the message.

**2. Why does GPG use this approach instead of encrypting the entire message with RSA?**

I wouldnt encrypt the entire message with rsa because it would be slow especially if used for a larger dataset. 2, RSA can only encrypt things smaller than its key size and a message could exceed this so there wouldnt be a clean one cut way of using RSA. and 3 RSA has weaknesses mathematically like n = p x q.

**3. What is this construction called?**

This construction is called hybric encryption

### 4.3 Sign, Verify, and Break

1. My Private key
2. my public key
3. The recipients public key
4. the recipients private key
5. without the signature theres no proof of who authorized the message. With the signature it tells you who it came from specifically and whoever holds the private key.

---

## Part 5: SSH Keys

### Written Answer

RSA relies of the difficulty of factoring large numbers, while ED25519 relies on the elliptic curve discrete log problem, with is harder to solver per bit of key. Making the security around the same. ED's smaller size reflects on the efficiency of the math so its not really a weakness.

---

## Part 7: Grading the Machine

### 7.1 Generate Cryptographic Code

- **AI assistant used:** Claude
- **Exact prompt:** “Write me a Python function that encrypts a file with AES.”

### 7.2 Critique the AI Code

The code has the defects 1. the code accepts a weak passcode, 2. it coded one error for two different failures, 3. The decrypted file is created with default permissions (0o644).

#### Defect 1: the code accepts a weak passcode

- **What could an attacker do:** An attacker could brute force this from a dictionary.
- **Lecture concept:** This was covered with encryption and how easy normal passwords could be bruteforced using a dictionary

#### Defect 2: it coded one error for two different failures

- **What could an attacker do:** I dont actually know what an attacker could do with this I just saw it while analyzing the code. Maybe they would be able to flip the failure so they see the correct passcode while the user sees an error message and continues trying.
- **Lecture concept:** I dont think we've talked about 2 specifically but It was mentioned where eve could intercept a message and tamper with it so the user getting the message couldnt tell.

#### Defect 3: The decrypted file is created with default permissions (0o644)

- **What could an attacker do:** An attacker could just straight up read the decryption file.
- **Lecture concept:** 3 violates permissions although they arent directory permissions.

### 7.3 Fix the Code

1. I changed the passphrase requirements so the password is atleast 12 characters when encrypting and made it so it is entered twice in the CLI. I changed this because It rejects an empty password and a weak password like pizza. I adressed a weak passphrase. 2. I changed how the output files are created, now they're created with the mode 0600 so only the owner can read the file. This addresses file permissions. I couldnt fix the swap issue myself.

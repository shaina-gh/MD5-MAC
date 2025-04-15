#🔐 HMAC-MD5 Implementation in Java

---

###📌 Author  : Shaina  

---

##🧠 What is HMAC-MD5?  
HMAC (Hash-based Message Authentication Code) is a mechanism for verifying data integrity and authenticity using a cryptographic hash function (MD5 in this case). MD5 (Message Digest Algorithm 5) produces a 128-bit hash value, commonly used to validate data integrity. HMAC combines a secret key with the message and applies the hash function twice for enhanced security.

---

**MD5 Core Operations**:  
- **Padding**: Adjust message length to align with 512-bit blocks.  
- **Block Processing**: Divide into 512-bit chunks and process via four rounds of bitwise operations.  
- **Bitwise Functions**: Non-linear functions (AND, OR, XOR, NOT) applied during rounds.  
- **Final Digest**: 128-bit output after processing all blocks.

---

**HMAC-MD5 Steps**:  
1. **Key Preparation**: Adjust key length to 64 bytes.  
2. **Inner/Outer Padding**: XOR key with `ipad` (0x36) and `opad` (0x5C).  
3. **Hashing**: Compute hash of `(key ⊕ ipad) + message`, then hash `(key ⊕ opad) + inner_hash`.

---

🎯 Objective  
This project demonstrates HMAC-MD5 for generating a Message Authentication Code (MAC) in Java, featuring:  
- MD5 hash function implementation.  
- HMAC key adjustment and padding.  
- Hex-encoded MAC output for verification.

---

🛠️ Features  
- HMAC-MD5 implementation compliant with RFC 2104.  
- Key handling (truncation/padding to 64 bytes).  
- Padding logic for MD5 alignment.  
- Hex string conversion for digest output.

---

🧪 HMAC-MD5 Procedure  
1. **Key Adjustment**:  
   - Truncate keys longer than 64 bytes to MD5 hash.  
   - Pad shorter keys with zeros to 64 bytes.  
2. **Inner Hash**:  
   - XOR key with `ipad` (0x36).  
   - Compute MD5 hash of `ipad + message`.  
3. **Outer Hash**:  
   - XOR key with `opad` (0x5C).  
   - Compute MD5 hash of `opad + inner_hash`.  
4. **MAC Output**: Convert final hash to a 32-character hex string.

---

▶️ How to Compile & Run  
```bash
javac HMACMD5.java
java HMACMD5
```

---

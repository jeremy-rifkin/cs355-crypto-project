## Final Project

**Security goals**
1. This protocol should be able to be run more than once with the same file between multiple parties.
2. The protocol should be secure against replay attacks.
3. Two parties can verify they have the same file with complete confidence.
4. If the parties do not share the same file, they shouldn't learn the confidential contents of the
   file from the other.
5. No illegitimate party or adversary on the network can learn the contents of the file.

**Note:** Our protocol ensures zero false positives but we do not care about false negatives. An
adversary on the network could flip random bits in the messages and cause either one or both of the
parties to fail to verify even when they do have the same file. We are not concerned with preventing
or even detecting this tampering: The adversary has nothing to gain from this and it would
effectively just be a DOS, which they could also achieve many other ways. The important thing is
both parties know with confidence they have the same database before deploying.

**Cryptographic assumptions:**
1. Sha3 is secure hash function
2. Sha3 is a random oracle
3. HMAC with Sha3 is a secure MAC

### Protocol

```
Both parties derive shared secret key k = Sha3(file)
Alice chooses two random 128-bit numbers n1 and n2 and sends {n1, n2, MAC_k({n1, n2})} to Bob
If the MAC does not verify, Bob aborts.
Bob chooses two random 128-bit numbers m1 and m2 and sends {m1, m2, n1 ⊕ n2, MAC_k({m1, m2, n1 ⊕ n2})} to Alice
If the MAC does not verify, Alice aborts.
Alice sends {m1 ⊕ m2, MAC_k({m1 ⊕ m2})} to Bob.
```

### Proof of security




### References

[1]: https://crypto.stackexchange.com/questions/72835/is-there-something-wrong-with-using-a-hash-function-as-a-prg/95901#comment-208695

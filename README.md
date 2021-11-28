## Final Project

**Security goals**
1. No illegitimate party or adversary on the network can learn the confidential contents of the file
   as a result of the protocol.
2. This protocol should be able to be run more than once with the same file between multiple
   parties and be secure against replay attacks.
3. Two parties verify they have the same file with complete confidence.

**Note:** Our protocol ensures zero false positives but we do not care about false negatives. An
adversary on the network could flip random bits in the messages and cause either one or both of the
parties to fail to verify even when they do have the same file. We are not concerned with preventing
or even detecting this tampering: The adversary has nothing to gain from this and it would
effectively just be a DOS, which they could also achieve many other ways. The important thing is
each party knows with confidence it has the same file as another party before deploying.

**Note:** Under our protocol if Alice and Bob have the company's file but Eve doesn't, Alice can
interfere with the protocol being run between Bob and Eve making them think they have the same file
even if they don't. We don't cover this as Alice has nothing to gain from it. This is consistent
with the project specification: Our non-adversary parties should only launch passive attacks.

**Cryptographic assumptions:**
1. SHA-3 is secure hash function
2. SHA-3 is a random oracle
3. HMAC with SHA-3 is a secure MAC
4. The password file is is unguessable

### Protocol

```
Both parties derive shared secret key k = SHA-3(file)
Alice chooses two random 128-bit numbers n1 and n2 and sends {n1, n2, MAC_k({n1, n2})} to Bob
If the MAC does not verify, Bob aborts.
Bob chooses two random 128-bit numbers m1 and m2 and sends {m1, m2, n1 ⊕ n2, MAC_k({m1, m2, n1 ⊕ n2})} to Alice
If the MAC does not verify, Alice aborts.
Alice sends {m1 ⊕ m2, MAC_k({m1 ⊕ m2})} to Bob.
```

### Proof of security

**Cryptographic assumptions:**
1. The security margin of Keccak SHA-3 is "substantially bigger" than that of SHA-256, which is
   still secure with no signs of an attack resulting in collisions any time soon [\[1\]].
2. "SHA-3 is designed for (and believed to meet) that goal" [\[2\]] "It turns out that a random
   sponge is as strong as a random oracle, except for the effects induced by the finite memory"
   [\[3\]]
3. HMAC is secure with any secure hash function, similar to what we proved in homework.
4. An adversary can guess the contents of the file naively with probability 1/2^4E9. But usernames
   and passwords aren't uniformly random: Suppose each username is 128 bits and each password is 128
   bits and this file consists of 31.25 million username-password pairs. Now suppose each username
   and each password can be guessed with probability 1/2. This is an extraordinary extreme case.
   Even in this case, the probability of correctly guessing the file's contents are exceedingly low:
   1/2^31.25E6. This is far lower than the probability of finding a collision in SHA-256 after
   computing one million hashes. Even if each pair can be guessed with 99% probability, you still
   have a better chance of finding a collision in SHA-256.



### References

[\[1\]]: https://eprint.iacr.org/2012/421.pdf
[\[2\]]: https://crypto.stackexchange.com/questions/72835/is-there-something-wrong-with-using-a-hash-function-as-a-prg/95901#comment-208695
[\[3\]]: https://keccak.team/sponge_duplex.html

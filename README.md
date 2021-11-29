## CS355 Final Project

- [Final Project](#final-project)
	- [Protocol](#protocol)
	- [Proof of security](#proof-of-security)
	- [References](#references)

### Protocol

**Security goals:**
1. No illegitimate party or adversary on the network can learn the confidential contents of the file
   as a result of the protocol.
2. This protocol should be able to be run more than once with the same file between multiple
   parties and be secure against replay attacks.
3. Two parties verify they have the same file with complete confidence.

**What we do not cover:**
- Our protocol ensures zero false positives but we do not care about false negatives. An adversary
  on the network could flip random bits in the messages and cause either one or both of the parties
  to fail to verify even when they do have the same file. We are not concerned with preventing or
  even detecting this tampering: The adversary has nothing to gain from this and it would
  effectively just be a DOS, which they could also achieve many other ways. The important thing is
  each party knows with confidence it has the same file as another party before deploying.
- Under our protocol if Alice and Bob have the company's file but Eve doesn't, Alice can interfere
  with the protocol being run between Bob and Eve making them think they have the same file even if
  they don't. We don't cover this as Alice has nothing to gain from it. This is consistent with the
  project specification: Our non-adversary parties should only launch passive attacks.
- We will assume the contents of the file are not leaked. If it is leaked, the company has bigger
  problems than just this protocol being compromised.

**Cryptographic assumptions:**
1. SHA-3 is secure hash function
2. SHA-3 is a random oracle
3. HMAC with SHA-3 is a secure MAC
4. The password file is is unguessable

```
1. Both parties derive shared secret key k = SHA-3(file)
2. Alice chooses two random 128-bit numbers n1 and n2 and sends {n1, n2, HMAC_k({n1, n2})} to Bob
3. If the MAC does not verify, Bob aborts.
4. Bob chooses two random 128-bit numbers m1 and m2 and sends {m1, m2, n1 ⊕ n2, HMAC_k({m1, m2, n1 ⊕ n2})} to Alice
5. If the MAC does not verify, Alice aborts.
6. Alice sends {m1 ⊕ m2, HMAC_k({m1 ⊕ m2})} to Bob.
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

**Security goals:**
1. Suppose, worst-case scenario, a party or adversary recovers `k` from the messages exchanged
   during the protocol. That is a problem for the protocol but not a problem as far as
   confidentiality goes: Knowing the hash of the file does not enable the adversary to reconstruct
   the contents of the file. It gives the adversary a means to check that guessed contents are
   correct, but the probability of guessing the correct contents are simply too low.
2. If the protocol used the values MAC'd each time, the protocol would be trivially susceptible to a
   replay attack: Adversary first observes Alice <-> Bob then replays. Similarly, if Alice first
   sends `{n, HMAC_k({n})}` and the Adversary is allowed to send back the HMAC of any number `m`,
   the Adversary can cause Alice to think they have the same file by just replaying a message. By
   constructing the protocol as a challenge: Alice challenges Bob to MAC as message containing
   `n1 ⊕ n2` and then Bob challenges Alice to MAC a message containing `m1 ⊕ m2` they can be
   confident that the other party legitimately knows `k` and is not just replaying, so long as the
   numbers `n1, n2, m1, m2` are all effectively random, or alternatively, `n1 ⊕ n2` and `m1 ⊕ m2`
   are effectively random. Even if the protocol is run two billion times the probability of finding
   a collision in `n1 ⊕ n2` or `m1 ⊕ m2` with 128-bit numbers is 1.4*10^-21, lower than the
   probability of finding a collision in SHA-256 after 10^30 (1 nonillion) guesses.
3. Security step-by-step
   1. Because SHA-3 is a random oracle and the file's contents are unguessable, `k = SHA-3(file)`
      gives both parties an unguessable and uniformly random key to use for MACs.
   2. The `{n1, n2, HMAC_k({n1, n2})}` message may be replayed by an Adversary but that doesn't
      matter.
   3. Aborting if the MAC fails to verify is important so Bob doesn't serve as an oracle for HMAC_k.
   4. 

   Given our cryptographic assumptions, the only way the protocol can be executed successfully



### References

1. https://eprint.iacr.org/2012/421.pdf
2. https://crypto.stackexchange.com/questions/72835/is-there-something-wrong-with-using-a-hash-function-as-a-prg/95901#comment-208695
3. https://keccak.team/sponge_duplex.html

[\[1\]]: https://eprint.iacr.org/2012/421.pdf
[\[2\]]: https://crypto.stackexchange.com/questions/72835/is-there-something-wrong-with-using-a-hash-function-as-a-prg/95901#comment-208695
[\[3\]]: https://keccak.team/sponge_duplex.html

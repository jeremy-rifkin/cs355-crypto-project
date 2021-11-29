## CS355 Final Project <!-- omit in toc -->

- [Goals and Assumptions](#goals-and-assumptions)
	- [Security goals](#security-goals)
	- [Cryptographic assumptions](#cryptographic-assumptions)
	- [Non-cryptographic assumptions](#non-cryptographic-assumptions)
	- [What we do not cover](#what-we-do-not-cover)
- [Protocol](#protocol)
- [Justification of Assumptions](#justification-of-assumptions)
	- [Cryptographic assumptions](#cryptographic-assumptions-1)
	- [Non-cryptographic assumptions](#non-cryptographic-assumptions-1)
- [Proof of Security](#proof-of-security)
	- [Security goals](#security-goals-1)
- [References](#references)

### Goals and Assumptions

#### Security goals
1. No illegitimate party or adversary on the network can learn the confidential contents of the file
   as a result of the protocol.
2. This protocol should be able to be run more than once with the same file between multiple
   parties and be secure against replay attacks.
3. Two parties verify they have the same file with complete confidence.

#### Cryptographic assumptions
1. SHA-3 is secure hash function
2. SHA-3 is a random oracle
3. HMAC with SHA-3 is a secure MAC
4. The password file is is unguessable

#### Non-cryptographic assumptions
1. Every party/subcontractor has some sort of unique name and knows who they're talking to.

#### What we do not cover
- Our protocol ensures zero false positives but we do not care about false negatives. An adversary
  on the network could flip random bits in the messages and cause either one or both of the parties
  to fail to verify even when they do have the same file. We are not concerned with preventing or
  even detecting this tampering: The adversary has nothing to gain from it and the attack would
  effectively just be a DOS, which they could also achieve many other ways. The important thing is
  each party knows with confidence it has the same file as another party before deploying.
- Under our protocol if Alice and Bob have the company's file but Eve doesn't, Alice can interfere
  with the protocol being run between Bob and Eve making them think they have the same file even if
  they don't. We don't cover this as Alice has nothing to gain from it. This is consistent with the
  project specification: Our non-adversary parties should only launch passive attacks.
- We will assume the contents of the file are not leaked. If it is leaked, the company has bigger
  problems than just this protocol being compromised.

### Protocol

```
1. Both parties derive shared secret key k = SHA-3(file)
2. P1 chooses two random 128-bit numbers n1 and n2 and sends
   {n1, n2, P1_name, HMAC_k({n1, n2, P1_name})} to P2
3. If the MAC or the name do not verify, P2 aborts.
4. P2 chooses two random 128-bit numbers m1 and m2 and sends
   {m1, m2, n1 ⊕ n2, P2_name, HMAC_k({m1, m2, n1 ⊕ n2, P2_name})} to P1
5. If the MAC or the name do not verify, P1 aborts.
6. P1 sends {m1 ⊕ m2, P1_name, HMAC_k({m1 ⊕ m2, P1_name})} to P2.
7. If the MAC or the name do not verify, P2 aborts.
```

### Justification of Assumptions

#### Cryptographic assumptions
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

#### Non-cryptographic assumptions
1. It's safe to assume every subcontractor has some sort of unique name and knows who they're
   talking to. Every party should know who they're talking to or supposed to be talking to in order
   for the protocol to even begin and an email address suffices for unique name.

### Proof of Security

#### Security goals
1. Suppose, in absolute worst-case scenario, a party or adversary recovers `k` from the messages
   exchanged during the protocol. That is a problem for the protocol but not a problem as far as
   confidentiality goes: Knowing the hash of the file does not enable the adversary to reconstruct
   the contents of the file. It gives the adversary a means to check that guessed contents are
   correct but the probability of guessing the correct contents are simply too low.
2. If the protocol used the same values under MAC each time the protocol would be trivially
   susceptible to a replay attack: Adversary first observes Alice <-> Bob then replays. Similarly,
   if Alice first sends `{n, HMAC_k({n})}` and the Adversary is allowed to send back the HMAC of any
   number `m`, the Adversary can cause Alice to think they have the same file by just replaying a
   message. By constructing the protocol as a challenge: Alice challenges Bob to MAC as message
   containing `n1 ⊕ n2` and then Bob challenges Alice to MAC a message containing `m1 ⊕ m2` they can
   be confident that the other party legitimately knows `k` and is not just replaying, so long as the
   numbers `n1`, `n2`, `m1`, `m2` (or alternatively `n1 ⊕ n2` and `m1 ⊕ m2`) are effectively random.
   Even if the protocol is run two billion times the probability of finding a collision in `n1 ⊕ n2`
   or `m1 ⊕ m2` with 128-bit numbers (i.e. the condition for a replay attack) is 1.4*10^-21, far
   lower than the probability of finding a collision in SHA-256 after 10^30 (1 nonillion) guesses.
3. After receiving `{n1, n2, P1_name, HMAC_k({n1, n2, P1_name})}` from P1, the only way P2 can reply
   with a properly authenticated message is to know `k`, which they can only know if they have the
   file. They cannot use another legitimate party running this protocol as an oracle because the
   response is required to contain the party's name. Similarly, P1 cannot reply to
   `{m1, m2, n1 ⊕ n2, P2_name, HMAC_k({m1, m2, n1 ⊕ n2, P2_name})}` without knowing `k` and another
   party cannot be used as an oracle to produce `{m1 ⊕ m2, P1_name, HMAC_k({m1 ⊕ m2, P1_name})}`
   either. Security against replays was covered previously. Given our cryptographic assumptions, the
   only way the protocol can be executed successfully

### References

1. https://eprint.iacr.org/2012/421.pdf
2. https://crypto.stackexchange.com/questions/72835/is-there-something-wrong-with-using-a-hash-function-as-a-prg/95901#comment-208695
3. https://keccak.team/sponge_duplex.html

[\[1\]]: https://eprint.iacr.org/2012/421.pdf
[\[2\]]: https://crypto.stackexchange.com/questions/72835/is-there-something-wrong-with-using-a-hash-function-as-a-prg/95901#comment-208695
[\[3\]]: https://keccak.team/sponge_duplex.html

## Final Project

Security goals
- This protocol should be able to be run more than once with the same file
- An adversary shouldn't learn the contents of the file

We do not care if an adversary does a DOS attack leading to two parties thinking they don't have the
same file when they really do. The important thing is that if we verify then we know for 100% sure.

Cryptographic assumptions:
- AES is CPA secure
- Sha3 is secure hash function
- Sha3's output is computationally indistinguishable from uniform randomness: "SHA-3 is designed for
  (and believed to meet) that goal" [1]

### Protocol

```
Following happens all under AES_k, blocks are chained throughout the communication:
Alice chooses two numbers n1 and n2 and sends them to Bob
Bob chooses two numbers m1 and m2 and send m1, m2, and n1 ⊕ n2 to Alice
Alice send bob m1 ⊕ m2
```

### Protocol idea




### References

[1]: https://crypto.stackexchange.com/questions/72835/is-there-something-wrong-with-using-a-hash-function-as-a-prg/95901#comment-208695

# fpast2l

[![Documentation](https://godoc.org/github.com/zrhmn/fpast2l?status.svg)](http://godoc.org/github.com/zrhmn/fpast2l)

[PASETO] is a specification for secure, stateless authentication tokens.
[fpast2l] is Go implementation of only the secret/symmetric part of [version 2]
of the PASETO spec.

There exists at least one implementation: [o1egl/paseto], that covers the
complete PASETO specification, is probably better written and better
documenting. You should be using that instead.

The aim of fpast2l is not to be a complete or compatible implementation of the
entire PASETO standard. It is written to meet specific needs and has no
ambition for any sort of general use.

The key aim is to implement fast `v2.local` token generation in pure-Go with
the least amount of garbage possible. It is currently not completely garbage
free, which is what the roadmap will focus on. It is, however, slightly faster
than o1egl's implementation and produces less garbage.

[fpast2l]: #
[o1egl/paseto]: https://github.com/o1egl/paseto
[PASETO]: https://github.com/paragonie/paseto
[version 2]: https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md

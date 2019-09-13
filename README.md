# fpast2l

[*PASETO*][what-is-paseto] is a specification for secure, stateless
authentication tokens. This package implements *only* the secret/symmetric
part of the [version 2][paseto-v2-spec] (`v2.local`) of *PASETO*.

There exists at least one implementation: [o1egl/paseto][o1egl-paseto], that
covers the complete *PASETO* specification, is better written and better
documented. You *most probably* should use that instead of *fpast2l*. The aim
of *fpast2l* is not to be a complete (or even compatible) implementation of the
*PASETO* standard. It is written to meet *specific* needs, and has no
aspiration for any sort of general use. As such, feature requests and PRs
adding unnecessary features will be ignored.

That said, the *one* aim is to implement `v2.local` token generation and
verification in pure-Go, with the least amount of garbage possible. It's not
currently *completely* garbage free, and most modifications in the near future
will address just this. It is, however, reasonably fast, faster than [o1egl's
implementation][o1egl-paseto] and aims to improve on that.

### Contributing
If the above makes sense and you're still interested, PRs addressing
unnecessary heap-allocation, improving safety and performance (in that order of
importance) are most welcome.

[what-is-paseto]: https://github.com/paragonie/paseto
[o1egl-paseto]: https://github.com/o1egl/paseto

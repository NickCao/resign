# resign
sign git commits with OpenPGP smartcards without using GnuPG

## motivation
I'm not a huge fan of GnuPG and OpenPGP, but for signing git commits, the only two well supported methods are OpenPGP and PIV. Take GitHub as an example, it does not support validating self-signed PIV certificates, leaving OpenPGP the only choice. Managing key materials is a challenging task, and I would leave that to hardware security tokens, namely, OpenPGP smartcards. However the only OpenPGP smartcards client that is feature complete is GnuPG, known for providing insecure defaults and having a bad UX. Thus here comes resign, a drop-in replacement of `gpg.program` for git, with zero configuration and just works with your smartcards.

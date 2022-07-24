# resign
make use of your OpenPGP smartcards without using GnuPG

## functionality
- [x] signature
- [x] decryption
- [x] authentication

## motivation
I'm not a huge fan of GnuPG and OpenPGP, but for signing git commits, the only two well supported methods are OpenPGP and PIV. Take GitHub as an example, it does not support validating self-signed PIV certificates, leaving OpenPGP the only choice. Managing key materials is a challenging task, and I would leave that to hardware security tokens, namely, OpenPGP smartcards. However the only OpenPGP smartcards client that is feature complete is GnuPG, known for providing insecure defaults and having a bad UX. Thus here comes resign, a drop-in replacement of `gpg.program` for git, with zero configuration and just works with your smartcards.

## architecture
resign consists of three components: a grpc speaking agent that talks with smartcards over pcsc, a proxy that translates the custom built grpc protocol into ssh agent protocol, a cli tool that resembles gpg to be called by git. The first two run in the same process to ease deployment.

## limitations
- cannot verify signatures due to lack of keyring management

## references
[GnuPG: Format of the –status-fd output](https://github.com/gpg/gnupg/blob/master/doc/DETAILS#format-of-the-status-fd-output)  
[git: GPG interface](https://github.com/git/git/blob/master/gpg-interface.c)

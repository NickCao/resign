# resign
make use of your OpenPGP smartcards without using GnuPG

## functionality
- [x] signature
- [x] decryption
- [x] authentication

## motivation
I'm not a huge fan of GnuPG and OpenPGP, but speaking of hardware security tokens, OpenPGP smartcards are the most widely available ones. However the only OpenPGP smartcards client that is feature complete is GnuPG, while known for providing insecure defaults and having a bad UX. Thus here comes resign, a set of programs to make use of your smartcards, with zero configuration and just works.

## architecture
- resign: standard compliant ssh-agent
- resign-gpg: partial implementation of gpg cli, for use with sops
- age-plugin-resign: age plugin

## limitations
- cannot verify signatures due to lack of keyring management

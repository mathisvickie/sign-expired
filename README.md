# sign-expired
Signtool modification for expired certificates

Hijacks dll (XmlLite) which loads into official signtool (digitaly signed by micro$oft) and allows signing with expired certificates. Compiled dllmain is XmlLite.dll which needs to be placed next to signtool.

Same command before and after patch dll was introduced:
![404](https://github.com/mathisvickie/sign-expired/blob/main/pic.png)

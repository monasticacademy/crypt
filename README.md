# crypt

Command-line interactive symmetric key cryptography.

Install:

    go install github.com/monasticacademy/crypt@latest

Encrypt

    crypt --encrypt test.txt   # will prompt for password

Decrypt

    crypt --decrypt test.txt.encrypted    # will prompt for password

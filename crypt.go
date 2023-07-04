package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

var salt = []byte{
	56, 78, 185, 170, 79, 135, 36, 227,
	37, 110, 177, 104, 178, 158, 197, 146,
}

func Main() error {
	var args struct {
		Encrypt []string `placeholder:"PATH"`
		Decrypt []string `placeholder:"PATH"`
	}
	p := arg.MustParse(&args)

	if len(args.Encrypt) == 0 && len(args.Decrypt) == 0 {
		p.Fail("you must provide one of --encrypt or --decrypt")
	}

	// prompt for password
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}
	fmt.Println()

	// derive a key
	key := pbkdf2.Key(password, salt, 4096, 32, sha1.New)

	// process paths
	for _, path := range args.Encrypt {
		err := process(path, key, encrypt)
		if err != nil {
			return err
		}
	}
	for _, path := range args.Decrypt {
		err := process(path, key, decrypt)
		if err != nil {
			return err
		}
	}

	return nil
}

func process(path string, key []byte, f func([]byte, []byte) ([]byte, error)) error {
	in, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	out, err := f(in, key)
	if err != nil {
		return err
	}

	var outpath string
	if strings.HasSuffix(path, ".encrypted") {
		outpath = strings.TrimSuffix(path, ".encrypted")
	} else {
		outpath = path + ".encrypted"
	}

	return os.WriteFile(outpath, out, os.ModePerm)
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func main() {
	if err := Main(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

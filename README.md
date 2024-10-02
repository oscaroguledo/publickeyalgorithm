Here's the updated `README.md` with your GitHub username included:

---

# Public Key Encryption Algorithm

This project is an implementation of a simple public key encryption algorithm using Python. It features key generation, message encryption, and decryption based on basic principles of cryptography, including modular arithmetic and prime number selection.

## Features

- **Key Generation**: Generates public and private keys based on the given key length.
- **Encryption**: Encrypts a plaintext message using the generated public key.
- **Decryption**: Decrypts the ciphertext using the generated private key.
- **Command-line Interface**: Accepts input either via the command line or through a text file.

## Getting Started

### Prerequisites

- Python 3.x

### Running the Program

1. Clone this repository:

```bash
git clone https://github.com/oscaroguledo/public-key-encryption.git
```

2. Navigate to the directory and run the `main` Python script:

```bash
cd public-key-encryption
python3 main.py
```

### Key Length Selection

You will be prompted to enter a key length. The longer the key length, the more secure the encryption, but it also increases the processing time.

### Message Input

After selecting the key length, you will be asked to provide a message either via:

- Command-line input (`C`), or
- From a text file (`T`).

If you choose the text file option, the file should exist in the current directory, and you will be prompted to enter the filename (e.g., `plaintext.txt`).

### Output

- The program will output a randomly generated public-private key pair.
- The encrypted message will be shown as a list of integers (ciphertext).
- After the encryption, the program will decrypt the message and display the original plaintext.

## Usage Example

1. **Key Length**: You can enter any integer (e.g., `5`).

```bash
Select your key length:
5
```

2. **Message Input**: You can choose to input a message via the command line or from a text file.

```bash
Enter message via command line or text file: C/T
C
Enter your message:
Hello world!
```

3. **Output**: The program will generate the public and private keys, show the encrypted message, and then decrypt it to display the original message.

Example output:

```
key: {'private_key': ([1, 2, 4, 8, 16], 37, 29), 'public_key': [1, 3, 5, 13, 26]}

Encrypting using the public key ...
5-bit plaintext : ['1101000', '1100101', '1101100', '1101100', '1101111', '0101110', '1101111', '1110010', '1101100', '1100100', '100000'] 

5-bit ciphertext: [216, 219, 100, 155, 260, 109, 231, 228] 

Decrypting using the private key ...
decrypted text: Hello world! 
```

### Key Details

- **Private Key**: Tuple consisting of `(e, q, w)`, where:
  - `e` is a randomly generated sequence of integers.
  - `q` is a prime number larger than twice the largest value in `e`.
  - `w` is a number co-prime with `q`.
  
- **Public Key**: A list `h`, which is generated based on the private key.

## Functions Overview

- `__alpha_to_binary(self, message)`: Converts the input message to a binary string.
- `__binary_to_aplha(self, binary_message)`: Converts a binary string back to text.
- `__get_e(self, n)`: Generates the random sequence `e` for the private key.
- `__is_prime(self, n)`: Determines if a number is prime.
- `__get_q(self, array)`: Generates the prime number `q` for the private key.
- `__get_w(self, q)`: Finds a number `w` that is co-prime with `q`.
- `gen_random_key(self)`: Generates and returns the public and private keys.
- `encrypt(self, message, key)`: Encrypts the message using the public key.
- `decrypt(self, cipher, key, pad)`: Decrypts the ciphertext using the private key.

## License

This project is licensed under the MIT License.

## Contributors

- [Oscar Oguledo](https://github.com/oscaroguledo)

Feel free to open an issue or submit a pull request if you'd like to contribute!

---

Feel free to make any additional changes or let me know if you need further assistance!

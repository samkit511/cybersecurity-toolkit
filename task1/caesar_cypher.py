def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    if mode == 'decrypt':
        shift = -shift
    
    for char in text:
        if char.isalpha():
            # Handle uppercase and lowercase separately
            base = ord('A') if char.isupper() else ord('a')
            # Shift character and wrap around the alphabet
            shifted = (ord(char) - base + shift) % 26 + base
            result += chr(shifted)
        else:
            # Non-alphabetical characters remain unchanged
            result += char
    return result


def main():
    print("Welcome to the Caesar Cipher program!")
    mode = input("Type 'encrypt' to encrypt or 'decrypt' to decrypt: ").strip().lower()
    if mode not in ['encrypt', 'decrypt']:
        print("Invalid mode selected. Please run the program again.")
        return

    text = input("Enter your message: ")
    try:
        shift = int(input("Enter shift value (integer): "))
    except ValueError:
        print("Invalid shift value. Please enter an integer.")
        return

    output = caesar_cipher(text, shift, mode)
    print(f"Result: {output}")

if __name__ == "__main__":
    main()

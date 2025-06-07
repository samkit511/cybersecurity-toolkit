from PIL import Image

def encrypt_decrypt_image(image_path, key, mode='encrypt'):
    # Open the image
    img = Image.open(image_path)
    img = img.convert('RGB')  # Ensure image is in RGB mode

    pixels = img.load()  # Pixel access object

    width, height = img.size

    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            if mode == 'encrypt':
                r = (r + key) % 256
                g = (g + key) % 256
                b = (b + key) % 256
            elif mode == 'decrypt':
                r = (r - key) % 256
                g = (g - key) % 256
                b = (b - key) % 256
            pixels[x, y] = (r, g, b)

    return img

def main():
    print("Simple Image Encryptor/Decryptor")
    mode = input("Type 'encrypt' to encrypt or 'decrypt' to decrypt an image: ").strip().lower()
    if mode not in ['encrypt', 'decrypt']:
        print("Invalid mode selected. Exiting.")
        return

    image_path = input("Enter the path to the image file: ").strip()
    try:
        key = int(input("Enter a numeric key (0-255): "))
        if not (0 <= key <= 255):
            raise ValueError("Key must be between 0 and 255.")
    except ValueError as e:
        print(f"Invalid key: {e}")
        return

    try:
        output_image = encrypt_decrypt_image(image_path, key, mode)
        output_filename = f"{mode}ed_image.png"
        output_image.save(output_filename)
        print(f"Image saved as {output_filename}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

